// Package dlna 提供局域网媒体发现与播放：SSDP 发现 + 最小 ContentDirectory。
// 只做发现与播放，不暴露文件管理（见 docs/01 第 9.3 节）。
//
// 刻意不引第三方 UPnP 库：只需要 Browse 一个动作，自研能直接让列举走索引，
// 而不是像多数库那样扫目录。
package dlna

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"fsgw/internal/audit"
	"fsgw/internal/index"
	"fsgw/internal/vfs"
)

type Config struct {
	FriendlyName string
	Port         int
}

type Server struct {
	cfg     Config
	v       *vfs.VFS
	st      *index.Store
	log     *slog.Logger
	aud     *audit.Log
	udn     string
	lanIP   string
	srv     *http.Server
	ln      net.Listener
	ssdp    *ssdpServer
	started bool
	ssdpOn  atomic.Bool
}

type Options struct {
	Config Config
	// DataDir 用来存随机的设备 UUID（dlna_udn.txt）。
	// 留空则退化为"主机名 + MAC"派生，仍是本机独有。
	DataDir string
	VFS     *vfs.VFS
	Store   *index.Store
	Log     *slog.Logger
	Audit   *audit.Log
}

func New(o Options) *Server {
	if o.Config.Port == 0 {
		o.Config.Port = 8200
	}
	if o.Config.FriendlyName == "" {
		o.Config.FriendlyName = "熬拜共享家"
	}
	ip := lanIPv4()
	return &Server{
		cfg:   o.Config,
		v:     o.VFS,
		st:    o.Store,
		log:   o.Log,
		aud:   o.Audit,
		udn:   resolveUDN(o.DataDir, o.Config.FriendlyName, o.Config.Port),
		lanIP: ip,
	}
}

// Start 起 HTTP 与 SSDP。SSDP 失败不致命：多播在某些网络里会被拦，
// 那时设备可以手动填 http://<ip>:<port>/rootDesc.xml 仍然能用。
func (s *Server) Start() error {
	addr := fmt.Sprintf("0.0.0.0:%d", s.cfg.Port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("DLNA 监听 %s 失败: %w", addr, err)
	}
	s.ln = ln
	s.srv = &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 10 * time.Second}
	go s.srv.Serve(ln)

	s.ssdp = newSSDP(s.lanIP, s.cfg.Port, s.udn, s.cfg.FriendlyName, s.log)
	if err := s.ssdp.Start(); err != nil {
		s.log.Warn("SSDP 启动失败，设备可能无法自动发现", "err", err)
		s.ssdp = nil
		s.ssdpOn.Store(false)
	} else {
		s.ssdpOn.Store(true)
	}
	s.started = true
	s.log.Info("DLNA 已启动", "addr", addr, "friendly", s.cfg.FriendlyName, "ip", s.lanIP,
		"udn", s.udn, "ssdp", s.ssdpOn.Load())
	return nil
}

// SSDPActive 报告设备发现（SSDP）是否真的起来了。
// HTTP 能用但 SSDP 挂了时，电视是搜不到的——状态里必须能区分这两种情况，
// 否则界面显示"已开启"而设备永远发现不了，排查时完全没有线索。
func (s *Server) SSDPActive() bool {
	return s.ssdpOn.Load()
}

func (s *Server) Stop() error {
	if !s.started {
		return nil
	}
	s.started = false
	s.ssdpOn.Store(false)
	if s.ssdp != nil {
		s.ssdp.Stop()
	}
	if s.srv != nil {
		return s.srv.Close()
	}
	return nil
}

func (s *Server) Addr() string {
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// LANAddr 返回更适合展示的地址：局域网 IP + 端口，而不是 [::]:8200。
func (s *Server) LANAddr() string {
	return fmt.Sprintf("%s:%d", s.lanIP, s.Port())
}

func (s *Server) Port() int {
	if s.ln == nil {
		return s.cfg.Port
	}
	if a, ok := s.ln.Addr().(*net.TCPAddr); ok {
		return a.Port
	}
	return s.cfg.Port
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/rootDesc.xml", s.deviceDesc)
	mux.HandleFunc("/ContentDirectory.xml", s.scpd)
	mux.HandleFunc("/ctl/ContentDirectory", s.control)
	mux.HandleFunc("/media/", s.media)
	// 其余一律 404：不提供目录列表页，也不做文件管理。
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	// 前置拦截 ".." 段。ServeMux 默认会把 /media/../rootDesc.xml 规范成 301
	// 重定向到清理后的路径——虽然走不出 URL 空间，但与其让客户端跟随到
	// 别的路由，不如在入口就拒绝。媒体面本来就不该出现 ".."。
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hasDotDot(r.URL.Path) {
			if s.aud != nil {
				s.aud.Write(audit.Entry{Source: "dlna", Action: "media", Result: "deny",
					Path: r.URL.Path, Detail: "路径包含 .. 段", Remote: r.RemoteAddr})
			}
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, r)
	})
}

// hasDotDot 按段判断，避免误伤 "a..b.mp4" 这类正常文件名。
func hasDotDot(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == ".." {
			return true
		}
	}
	return false
}

// ---------- 设备描述 ----------

func (s *Server) deviceDesc(w http.ResponseWriter, r *http.Request) {
	body := fmt.Sprintf(`<?xml version="1.0" encoding="utf-8"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:MediaServer:1</deviceType>
    <friendlyName>%s</friendlyName>
    <manufacturer>fsgw</manufacturer>
    <manufacturerURL>http://127.0.0.1/</manufacturerURL>
    <modelDescription>fsgw media server</modelDescription>
    <modelName>fsgw</modelName>
    <modelNumber>0.1.0</modelNumber>
    <UDN>uuid:%s</UDN>
    <serviceList>
      <service>
        <serviceType>urn:schemas-upnp-org:service:ContentDirectory:1</serviceType>
        <serviceId>urn:upnp-org:serviceId:ContentDirectory</serviceId>
        <SCPDURL>/ContentDirectory.xml</SCPDURL>
        <controlURL>/ctl/ContentDirectory</controlURL>
        <eventSubURL>/evt/ContentDirectory</eventSubURL>
      </service>
    </serviceList>
  </device>
</root>`, xmlEscape(s.cfg.FriendlyName), s.udn)

	w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Write([]byte(body))
}

func (s *Server) scpd(w http.ResponseWriter, r *http.Request) {
	body := `<?xml version="1.0" encoding="utf-8"?>
<scpd xmlns="urn:schemas-upnp-org:service-1-0">
  <specVersion><major>1</major><minor>0</minor></specVersion>
  <actionList>
    <action>
      <name>Browse</name>
      <argumentList>
        <argument><name>ObjectID</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_ObjectID</relatedStateVariable></argument>
        <argument><name>BrowseFlag</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_BrowseFlag</relatedStateVariable></argument>
        <argument><name>Filter</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_Filter</relatedStateVariable></argument>
        <argument><name>StartingIndex</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_Index</relatedStateVariable></argument>
        <argument><name>RequestedCount</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_Count</relatedStateVariable></argument>
        <argument><name>SortCriteria</name><direction>in</direction><relatedStateVariable>A_ARG_TYPE_SortCriteria</relatedStateVariable></argument>
        <argument><name>Result</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_Result</relatedStateVariable></argument>
        <argument><name>NumberReturned</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_Count</relatedStateVariable></argument>
        <argument><name>TotalMatches</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_Count</relatedStateVariable></argument>
        <argument><name>UpdateID</name><direction>out</direction><relatedStateVariable>A_ARG_TYPE_UpdateID</relatedStateVariable></argument>
      </argumentList>
    </action>
  </actionList>
  <serviceStateTable>
    <stateVariable sendEvents="no"><name>A_ARG_TYPE_ObjectID</name><dataType>string</dataType></stateVariable>
    <stateVariable sendEvents="no"><name>A_ARG_TYPE_Result</name><dataType>string</dataType></stateVariable>
    <stateVariable sendEvents="no"><name>A_ARG_TYPE_BrowseFlag</name><dataType>string</dataType>
      <allowedValueList><allowedValue>BrowseMetadata</allowedValue><allowedValue>BrowseDirectChildren</allowedValue></allowedValueList>
    </stateVariable>
    <stateVariable sendEvents="no"><name>A_ARG_TYPE_Filter</name><dataType>string</dataType></stateVariable>
    <stateVariable sendEvents="no"><name>A_ARG_TYPE_SortCriteria</name><dataType>string</dataType></stateVariable>
    <stateVariable sendEvents="no"><name>A_ARG_TYPE_Index</name><dataType>ui4</dataType></stateVariable>
    <stateVariable sendEvents="no"><name>A_ARG_TYPE_Count</name><dataType>ui4</dataType></stateVariable>
    <stateVariable sendEvents="no"><name>A_ARG_TYPE_UpdateID</name><dataType>ui4</dataType></stateVariable>
  </serviceStateTable>
</scpd>`
	w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
	w.Write([]byte(body))
}

// ---------- Browse ----------

type soapEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Body    struct {
		Browse struct {
			ObjectID       string `xml:"ObjectID"`
			BrowseFlag     string `xml:"BrowseFlag"`
			StartingIndex  int    `xml:"StartingIndex"`
			RequestedCount int    `xml:"RequestedCount"`
		} `xml:"Browse"`
	} `xml:"Body"`
}

type didlObject struct {
	ID         string
	ParentID   string
	Title      string
	Class      string
	IsDir      bool
	ChildCount int
	Size       int64
	Mime       string
	URL        string
}

func (s *Server) control(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var env soapEnvelope
	if err := xml.NewDecoder(r.Body).Decode(&env); err != nil {
		soapFault(w, 402, "无法解析 SOAP 请求")
		return
	}
	req := env.Body.Browse
	if req.BrowseFlag == "" {
		req.BrowseFlag = "BrowseDirectChildren"
	}

	objects, total, err := s.browse(req.ObjectID, req.BrowseFlag)
	if err != nil {
		soapFault(w, 701, err.Error())
		return
	}
	if req.StartingIndex > 0 && req.StartingIndex < len(objects) {
		objects = objects[req.StartingIndex:]
	}
	if req.RequestedCount > 0 && req.RequestedCount < len(objects) {
		objects = objects[:req.RequestedCount]
	}

	w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
	fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
<s:Body>
<u:BrowseResponse xmlns:u="urn:schemas-upnp-org:service:ContentDirectory:1">
<Result>`+xmlEscape(didl(objects))+`</Result>
<NumberReturned>`+strconv.Itoa(len(objects))+`</NumberReturned>
<TotalMatches>`+strconv.Itoa(total)+`</TotalMatches>
<UpdateID>1</UpdateID>
</u:BrowseResponse>
</s:Body>
</s:Envelope>`)

	if s.aud != nil {
		s.aud.Write(audit.Entry{Source: "dlna", Action: "Browse", Path: req.ObjectID, Result: "ok",
			Detail: fmt.Sprintf("返回 %d 项", len(objects))})
	}
}

func soapFault(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", `text/xml; charset="utf-8"`)
	w.WriteHeader(http.StatusInternalServerError)
	fmt.Fprintf(w, `<?xml version="1.0" encoding="utf-8"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">
<s:Body><s:Fault><faultcode>s:Client</faultcode><faultstring>UPnPError</faultstring>
<detail><UPnPError xmlns="urn:schemas-upnp-org:control-1-0"><errorCode>%d</errorCode><errorDescription>%s</errorDescription></UPnPError></detail>
</s:Fault></s:Body></s:Envelope>`, code, xmlEscape(msg))
}

// browse 按 ObjectID 返回直接子项。ObjectID 约定：
//
//	0           根
//	sh:<name>   共享容器
//	d:<name>:<relKey>   目录
//	f:<name>:<relKey>   文件
func (s *Server) browse(objectID, flag string) ([]didlObject, int, error) {
	if flag == "BrowseMetadata" {
		obj, err := s.metadata(objectID)
		if err != nil {
			return nil, 0, err
		}
		return []didlObject{obj}, 1, nil
	}

	if objectID == "" || objectID == "0" {
		var out []didlObject
		for _, sh := range s.v.Shares() {
			if !sh.Media {
				continue
			}
			out = append(out, didlObject{
				ID:       "sh:" + sh.Name,
				ParentID: "0",
				Title:    sh.Name,
				Class:    "object.container.storageFolder",
				IsDir:    true,
			})
		}
		return out, len(out), nil
	}

	share, relKey, kind, err := s.parseID(objectID)
	if err != nil {
		return nil, 0, err
	}
	if kind == "" {
		return nil, 0, fmt.Errorf("对象不存在: %s", objectID)
	}
	if kind == "f" {
		obj, err := s.metadata(objectID)
		if err != nil {
			return nil, 0, err
		}
		return []didlObject{obj}, 1, nil
	}

	rows, err := s.st.ReadDir(relKey)
	if err != nil {
		return nil, 0, err
	}
	out := make([]didlObject, 0, len(rows))
	for _, row := range rows {
		if row.Kind == index.KindDir {
			out = append(out, didlObject{
				ID:       "d:" + share.Name + ":" + row.PathKey,
				ParentID: objectID,
				Title:    row.Name,
				Class:    "object.container.storageFolder",
				IsDir:    true,
			})
			continue
		}
		mime := mediaMime(row.Name)
		if mime == "" {
			continue // 非媒体类型一律不暴露
		}
		out = append(out, didlObject{
			ID:       "f:" + share.Name + ":" + row.PathKey,
			ParentID: objectID,
			Title:    row.Name,
			Class:    upnpClass(mime),
			Size:     row.Size,
			Mime:     mime,
			URL:      s.mediaURL(share.Name, row.Path),
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].IsDir != out[j].IsDir {
			return out[i].IsDir
		}
		return strings.ToLower(out[i].Title) < strings.ToLower(out[j].Title)
	})
	return out, len(out), nil
}

func (s *Server) metadata(objectID string) (didlObject, error) {
	if objectID == "0" || objectID == "" {
		return didlObject{ID: "0", ParentID: "-1", Title: s.cfg.FriendlyName,
			Class: "object.container.storageFolder", IsDir: true}, nil
	}
	share, relKey, kind, err := s.parseID(objectID)
	if err != nil {
		return didlObject{}, err
	}
	if kind == "sh" {
		return didlObject{ID: objectID, ParentID: "0", Title: share.Name,
			Class: "object.container.storageFolder", IsDir: true}, nil
	}
	row, err := s.st.ByPath(relKey)
	if err != nil {
		return didlObject{}, fmt.Errorf("对象不存在: %s", objectID)
	}
	if kind == "d" {
		return didlObject{ID: objectID, ParentID: parentIDOf(share.Name, row.ParentPath),
			Title: row.Name, Class: "object.container.storageFolder", IsDir: true}, nil
	}
	mime := mediaMime(row.Name)
	if mime == "" {
		return didlObject{}, fmt.Errorf("不是媒体文件: %s", row.Name)
	}
	return didlObject{
		ID: objectID, ParentID: parentIDOf(share.Name, row.ParentPath),
		Title: row.Name, Class: upnpClass(mime), Size: row.Size, Mime: mime,
		URL: s.mediaURL(share.Name, row.Path),
	}, nil
}

func parentIDOf(shareName, parentPath string) string {
	if parentPath == "" {
		return "sh:" + shareName
	}
	return "d:" + shareName + ":" + parentPath
}

// parseID 拆解 ObjectID，返回共享、相对路径键、类型（sh/d/f）。
func (s *Server) parseID(objectID string) (vfs.Share, string, string, error) {
	parts := strings.SplitN(objectID, ":", 3)
	if len(parts) < 2 {
		return vfs.Share{}, "", "", fmt.Errorf("非法 ObjectID: %s", objectID)
	}
	kind, name := parts[0], parts[1]
	share, ok := s.v.ShareByName(name)
	if !ok || !share.Media {
		return vfs.Share{}, "", "", fmt.Errorf("未知的媒体共享: %s", name)
	}
	relKey := ""
	if len(parts) == 3 {
		relKey = parts[2]
	}
	return share, relKey, kind, nil
}

func (s *Server) mediaURL(shareName, rel string) string {
	segs := strings.Split(rel, "/")
	for i, seg := range segs {
		segs[i] = url.PathEscape(seg)
	}
	return fmt.Sprintf("http://%s:%d/media/%s/%s", s.lanIP, s.Port(), shareName, strings.Join(segs, "/"))
}

func didl(objs []didlObject) string {
	var b strings.Builder
	b.WriteString(`<DIDL-Lite xmlns="urn:schemas-upnp-org:metadata-1-0/DIDL-Lite/" `)
	b.WriteString(`xmlns:dc="http://purl.org/dc/elements/1.1/" `)
	b.WriteString(`xmlns:upnp="urn:schemas-upnp-org:metadata-1-0/upnp/">`)
	for _, o := range objs {
		if o.IsDir {
			b.WriteString(fmt.Sprintf(`<container id="%s" parentID="%s" restricted="1" searchable="0">`,
				xmlEscape(o.ID), xmlEscape(o.ParentID)))
			b.WriteString("<dc:title>" + xmlEscape(o.Title) + "</dc:title>")
			b.WriteString("<upnp:class>" + o.Class + "</upnp:class>")
			b.WriteString("</container>")
			continue
		}
		b.WriteString(fmt.Sprintf(`<item id="%s" parentID="%s" restricted="1">`,
			xmlEscape(o.ID), xmlEscape(o.ParentID)))
		b.WriteString("<dc:title>" + xmlEscape(o.Title) + "</dc:title>")
		b.WriteString("<upnp:class>" + o.Class + "</upnp:class>")
		b.WriteString(fmt.Sprintf(`<res protocolInfo="http-get:*:%s:*" size="%d">%s</res>`,
			o.Mime, o.Size, xmlEscape(o.URL)))
		b.WriteString("</item>")
	}
	b.WriteString("</DIDL-Lite>")
	return b.String()
}

// ---------- 媒体字节 ----------

func (s *Server) media(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/media/")
	segs := strings.SplitN(rest, "/", 2)
	if len(segs) != 2 {
		http.NotFound(w, r)
		return
	}
	share, ok := s.v.ShareByName(segs[0])
	if !ok || !share.Media {
		http.NotFound(w, r)
		return
	}
	unescaped, err := url.PathUnescape(segs[1])
	if err != nil {
		http.Error(w, "bad path", http.StatusBadRequest)
		return
	}
	res, err := s.v.Resolve(share, unescaped)
	if err != nil {
		if s.aud != nil {
			s.aud.Write(audit.Entry{Source: "dlna", Action: "GET media", Path: unescaped, Result: "deny", Detail: err.Error()})
		}
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	// 只放行媒体类型，避免把共享里的文档也带出去。
	mime := mediaMime(res.Rel)
	if mime == "" {
		http.Error(w, "not a media file", http.StatusForbidden)
		return
	}
	row, err := s.st.ByPath(res.Key)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(res.Abs)
	if err != nil {
		http.Error(w, "backend read failed", http.StatusBadGateway)
		return
	}
	defer f.Close()

	w.Header().Set("Content-Type", mime)
	// 电视播放器普遍依赖 Range 做拖动。
	http.ServeContent(w, r, row.Name, time.Unix(0, row.MtimeNs), f)
}

// ---------- 媒体类型 ----------

var mediaTypes = map[string]string{
	".mp4": "video/mp4", ".m4v": "video/x-m4v", ".mkv": "video/x-matroska",
	".avi": "video/x-msvideo", ".mov": "video/quicktime", ".ts": "video/mp2t",
	".webm": "video/webm", ".flv": "video/x-flv", ".wmv": "video/x-ms-wmv",
	".mpg": "video/mpeg", ".mpeg": "video/mpeg", ".rmvb": "video/vnd.rn-realvideo",
	".mp3": "audio/mpeg", ".flac": "audio/flac", ".aac": "audio/aac",
	".m4a": "audio/mp4", ".wav": "audio/wav", ".ogg": "audio/ogg",
	".wma": "audio/x-ms-wma", ".ape": "audio/x-ape",
	".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".png": "image/png",
	".gif": "image/gif", ".bmp": "image/bmp", ".webp": "image/webp",
	".heic": "image/heic", ".tif": "image/tiff", ".tiff": "image/tiff",
}

func mediaMime(name string) string {
	i := strings.LastIndex(name, ".")
	if i < 0 {
		return ""
	}
	return mediaTypes[strings.ToLower(name[i:])]
}

func upnpClass(mime string) string {
	switch {
	case strings.HasPrefix(mime, "video/"):
		return "object.item.videoItem"
	case strings.HasPrefix(mime, "audio/"):
		return "object.item.audioItem.musicTrack"
	case strings.HasPrefix(mime, "image/"):
		return "object.item.imageItem.photo"
	}
	return "object.item"
}

func xmlEscape(s string) string {
	var b strings.Builder
	xml.EscapeText(&b, []byte(s))
	return b.String()
}

// ---------- 网络辅助 ----------

// lanIPv4 挑一个"能对外代表这台机器"的 IPv4。
//
// 不能简单地取"第一个私网地址"：Windows 上装了 Hyper-V / VMware / WSL 之后，
// 虚拟交换机的 172.x 往往排在物理网卡前面，按顺序取就会拿到 172.31.208.1
// 这种只有本机能到的地址。SSDP 把它当 LOCATION 宣告出去，电视会去拉
// http://172.31.208.1:8200/rootDesc.xml，跨网段必然超时——表现就是
// "DLNA 明明开着，电视里却看不到这个设备"。Linux 上只有一块网卡，所以没这毛病。
//
// 所以先问路由表：向公网地址 connect 一个 UDP socket（不真的发包，
// connect 只查一次路由），系统会填上默认出口的本地地址；拿不到再退回
// 按接口扫描，并且跳过虚拟网卡。这个结果只用于界面展示和兜底，
// SSDP 应答本身已经改成按网卡各报各的地址（见 ssdp.go）。
func lanIPv4() string {
	if ip := outboundIPv4(); ip != "" {
		return ip
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "127.0.0.1"
	}
	var private, any string
	for _, ifi := range ifaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		virtual := isVirtualIface(ifi.Name)
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipnet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
				continue
			}
			s := ip4.String()
			if !virtual && isPrivateIPv4(ip4) {
				return s
			}
			if !virtual && private == "" {
				private = s
			}
			if any == "" {
				any = s
			}
		}
	}
	if private != "" {
		return private
	}
	if any != "" {
		return any
	}
	return "127.0.0.1"
}

// outboundIPv4 借助路由表问出默认出口的本地地址。
func outboundIPv4() string {
	// 223.5.5.5 是阿里 DNS，只用来触发选路，UDP connect 不会发出任何包。
	conn, err := net.Dial("udp4", "223.5.5.5:53")
	if err != nil {
		return ""
	}
	defer conn.Close()
	ua, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return ""
	}
	ip4 := ua.IP.To4()
	if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
		return ""
	}
	// 默认路由偶尔会走虚拟网卡（比如 Hyper-V 的 NAT），那种地址同样宣告不出去。
	if name := ifaceNameOfIP(ip4); name != "" && isVirtualIface(name) {
		return ""
	}
	return ip4.String()
}

// ifaceNameOfIP 找出这个地址挂在哪块网卡上。
func ifaceNameOfIP(ip net.IP) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifi := range ifaces {
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok && ipnet.IP.Equal(ip) {
				return ifi.Name
			}
		}
	}
	return ""
}

// isVirtualIface 判断是不是虚拟/隧道网卡。
// 名字来自 Windows 的适配器名（"vEthernet (Default Switch)"、
// "VMware Network Adapter VMnet8"）和 Linux 的 docker0 / br-xxx 等。
func isVirtualIface(name string) bool {
	n := strings.ToLower(name)
	for _, p := range []string{
		"vethernet", "hyper-v", "vmware", "virtualbox", "vbox",
		"loopback", "wsl", "docker", "br-", "virbr",
		"tailscale", "zerotier", "wireguard",
		"tap-", "tun", "npcap", "bluetooth", "蓝牙",
	} {
		if strings.Contains(n, p) {
			return true
		}
	}
	return false
}

// isPrivateIPv4 判断 RFC1918 私网地址。
func isPrivateIPv4(ip net.IP) bool {
	ip4 := ip.To4()
	if ip4 == nil {
		return false
	}
	switch {
	case ip4[0] == 10:
		return true
	case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
		return true
	case ip4[0] == 192 && ip4[1] == 168:
		return true
	}
	return false
}

// UDN 是 SSDP 的去重键：客户端靠它判断"这是不是同一台设备"，
// 所以必须满足"同一台机器重启后不变、不同机器绝不相同"。
//
// 早先直接 md5(名称+端口)，只要两台机器配置一样就撞车——Windows 版和
// Linux 版默认都是"家庭共享:8200"，于是两台机器在局域网上宣告同一个
// UUID。电视按 UUID 去重，只会保留其中一个（先应答或先缓存的），另一个
// 无论怎么刷新都出不来。这就是"Linux 那边能 dela，Windows 这边看不到"。
//
// 现在改成落盘的随机 UUID：第一次用到生成一个写进 <data_dir>/dlna_udn.txt，
// 之后一直复用它，换机器、换目录都各是各的。
func resolveUDN(dataDir, name string, port int) string {
	if dataDir != "" {
		p := filepath.Join(dataDir, "dlna_udn.txt")
		if b, err := os.ReadFile(p); err == nil {
			if u := strings.TrimSpace(string(b)); validUDN(u) {
				return u
			}
		}
		u := randomUDN()
		if err := os.MkdirAll(dataDir, 0o755); err == nil {
			_ = os.WriteFile(p, []byte(u+"\n"), 0o644)
		}
		return u
	}
	return hostUDN(name, port)
}

// validUDN 校验 8-4-4-4-12 的十六进制形态，防止文件被写坏后把畸形 UDN 播出去。
func validUDN(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if s[i] != '-' {
				return false
			}
			continue
		}
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

func randomUDN() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return hostUDN("", 0)
	}
	b[6] = b[6]&0x0f | 0x40 // version 4
	b[8] = b[8]&0x3f | 0x80 // RFC4122 variant
	return formatUUID(b[:])
}

// hostUDN 是落盘失败（只读目录等）时的兜底：
// 用主机名 + 第一块网卡的 MAC 派生，仍然是"这台机器独有"的值。
func hostUDN(name string, port int) string {
	seed := "fsgw-dlna"
	if h, err := os.Hostname(); err == nil {
		seed += "|" + h
	}
	if ifaces, err := net.Interfaces(); err == nil {
		for _, ifi := range ifaces {
			if len(ifi.HardwareAddr) >= 6 {
				seed += "|" + ifi.HardwareAddr.String()
				break
			}
		}
	}
	seed += fmt.Sprintf("|%s|%d", name, port)
	sum := md5.Sum([]byte(seed))
	return formatUUID(sum[:16])
}

func formatUUID(b []byte) string {
	h := hex.EncodeToString(b)
	return fmt.Sprintf("%s-%s-%s-%s-%s", h[0:8], h[8:12], h[12:16], h[16:20], h[20:32])
}
