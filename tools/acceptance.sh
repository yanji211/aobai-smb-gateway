#!/bin/sh
# WebDAV + DLNA 端到端验收。只读探测，不改任何数据。
# 用法：./tools/acceptance.sh [口令]
set -u

WD="http://127.0.0.1:8443"
DL="http://127.0.0.1:8200"
PW="${1:-changeme}"
U="fsgw:$PW"
PASS=0; FAIL=0
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP" 2>/dev/null || true' EXIT

# md5sum 遇到特殊路径会在行首加 "\" 转义前缀，用重定向只算内容，
# 避免把文件名带进比较、也避开转义。
md5of() { md5sum < "$1" | cut -d' ' -f1; }

ok()   { PASS=$((PASS+1)); printf '  [PASS] %-34s %s\n' "$1" "${2:-}"; }
bad()  { FAIL=$((FAIL+1)); printf '  [FAIL] %-34s %s\n' "$1" "${2:-}"; }
chk()  { if [ "$2" = "$3" ]; then ok "$1" "$2"; else bad "$1" "期望 $3，实得 $2"; fi }

code() { curl -s --noproxy '*' -o /dev/null -w '%{http_code}' "$@"; }

echo "========== WebDAV =========="
chk "无认证拒绝"        "$(code -X PROPFIND -H 'Depth: 0' "$WD/share/")" 401
chk "错口令拒绝"        "$(code -u 'fsgw:definitely-wrong' -X PROPFIND -H 'Depth: 0' "$WD/share/")" 401
chk "正确口令放行"      "$(code -u "$U" -X PROPFIND -H 'Depth: 0' "$WD/share/")" 207

AUTHHDR=$(curl -s --noproxy '*' -I -X PROPFIND "$WD/share/" | tr -d '\r' | grep -i '^www-authenticate:' | head -1)
case "$AUTHHDR" in *Basic*) ok "认证挑战为 Basic" "$AUTHHDR" ;; *) bad "认证挑战为 Basic" "$AUTHHDR" ;; esac

MG=$(mktemp -d "$TMP/XXXXXX")
curl -s --noproxy '*' -u "$U" -o "$MG/page.html" -w '%{http_code}' "$WD/share/" > "$MG/idx.code"
XD=$(cat "$MG/idx.code")
chk "浏览器目录页 200"  "$XD" 200
if grep -q '<a href=' "$MG/page.html" 2>/dev/null; then
  ok "目录页含条目链接" "$(grep -c '<a href=' "$MG/page.html") 个"
else
  bad "目录页含条目链接" "无链接"
fi

VF="/d/share/测试视频.mp4"
curl -s --noproxy '*' -u "$U" -o "$MG/dl.mp4" -w '%{http_code}' "$WD/share/%E6%B5%8B%E8%AF%95%E8%A7%86%E9%A2%91.mp4" > "$MG/get.code"
chk "GET 文件 200"      "$(cat "$MG/get.code")" 200
if [ -f "$VF" ]; then
  A=$(md5of "$VF"); B=$(md5of "$MG/dl.mp4")
  if [ "$A" = "$B" ]; then ok "GET 字节一致" "$A"; else bad "GET 字节一致" "磁盘 $A / 下载 $B"; fi
fi

HH=$(curl -s --noproxy '*' -I -u "$U" "$WD/share/%E6%B5%8B%E8%AF%95%E8%A7%86%E9%A2%91.mp4" | tr -d '\r')
# 响应头名大小写由 Go 规范化（ETag → Etag），比较时统一转小写。
HHL=$(printf '%s' "$HH" | tr 'A-Z' 'a-z')
for h in "content-length: 1024" "accept-ranges: bytes" "etag:"; do
  case "$HHL" in *"$h"*) ok "HEAD 含 $h" "" ;; *) bad "HEAD 含 $h" "缺失" ;; esac
done

chk "Range 部分内容"    "$(code -u "$U" -r 100-199 "$WD/share/%E6%B5%8B%E8%AF%95%E8%A7%86%E9%A2%91.mp4")" 206

ET=$(printf '%s' "$HH" | grep -i '^etag:' | cut -d' ' -f2)
chk "ETag 命中返回 304"  "$(code -u "$U" -H "If-None-Match: $ET" "$WD/share/%E6%B5%8B%E8%AF%95%E8%A7%86%E9%A2%91.mp4")" 304

DEPTH1=$(curl -s --noproxy '*' -u "$U" -X PROPFIND -H 'Depth: 1' "$WD/share/" | grep -c '<D:href>')
if [ "$DEPTH1" -ge 6 ]; then ok "Depth:1 列举" "$DEPTH1 项"; else bad "Depth:1 列举" "只有 $DEPTH1 项"; fi

for m in PUT DELETE MKCOL MOVE COPY PROPPATCH; do
  chk "写方法 $m 被拒" "$(code -u "$U" -X "$m" -H 'Depth: 0' "$WD/share/probe.txt")" 405
done

chk "穿越 ../ 拒绝"     "$(code -u "$U" --path-as-is "$WD/share/../../Windows/win.ini")" 403
chk "穿越 ..%2f 拒绝"   "$(code -u "$U" --path-as-is "$WD/share/..%2f..%2fWindows/win.ini")" 403
chk "不存在路径 404"    "$(code -u "$U" "$WD/share/definitely-not-here.txt")" 404
chk "未知共享名拒绝"    "$(code -u "$U" "$WD/nosuchshare/")" 403

echo
echo "========== DLNA HTTP =========="
DESC=$(curl -s --noproxy '*' "$DL/rootDesc.xml")
DCODE=$(code "$DL/rootDesc.xml")
chk "设备描述 200"      "$DCODE" 200
case "$DESC" in
  *MediaServer:1*)    ok "声明 MediaServer:1" "" ;;
  *)                  bad "声明 MediaServer:1" "缺失" ;;
esac
case "$DESC" in
  *ContentDirectory*) ok "声明 ContentDirectory" "" ;;
  *)                  bad "声明 ContentDirectory" "缺失" ;;
esac

chk "SCPD 可读"         "$(code "$DL/ContentDirectory.xml")" 200
if curl -s --noproxy '*' "$DL/ContentDirectory.xml" | grep -q '<name>Browse</name>'; then
  ok "SCPD 含 Browse 动作" ""
else
  bad "SCPD 含 Browse 动作" "缺失"
fi

soap() {
  cat > "$TMP/req.xml" <<EOF
<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><u:Browse xmlns:u="urn:schemas-upnp-org:service:ContentDirectory:1"><ObjectID>$1</ObjectID><BrowseFlag>BrowseDirectChildren</BrowseFlag><Filter>*</Filter><StartingIndex>0</StartingIndex><RequestedCount>100</RequestedCount><SortCriteria></SortCriteria></u:Browse></s:Body></s:Envelope>
EOF
  curl -s --noproxy '*' -X POST -H 'Content-Type: text/xml; charset=utf-8' \
    -H 'SOAPAction: "urn:schemas-upnp-org:service:ContentDirectory:1#Browse"' \
    --data @"$TMP/req.xml" "$DL/ctl/ContentDirectory"
}
dec() { sed 's/&lt;/</g; s/&gt;/>/g; s/&quot;/"/g; s/&#34;/"/g; s/&amp;/\&/g'; }

soap "0" | dec > "$TMP/root.xml"
if grep -q '<container id="sh:share"' "$TMP/root.xml"; then ok "Browse 根返回共享容器" ""; else bad "Browse 根返回共享容器" "缺失"; fi

soap "sh:share" | dec > "$TMP/share.xml"
VID=$(grep -c 'object.item.videoItem' "$TMP/share.xml")
AUD=$(grep -c 'object.item.audioItem' "$TMP/share.xml")
DIR=$(grep -c 'object.container' "$TMP/share.xml")
if [ "$VID" -ge 1 ] && [ "$AUD" -ge 1 ]; then ok "媒体类型映射" "视频 $VID / 音频 $AUD"; else bad "媒体类型映射" "视频 $VID / 音频 $AUD"; fi
if [ "$DIR" -ge 1 ]; then ok "子目录以容器列出" "$DIR 个"; else bad "子目录以容器列出" "0 个"; fi
if grep -q '报价单\|说明\.pdf' "$TMP/share.xml"; then bad "文档未泄漏" "出现了文档"; else ok "文档未泄漏" ""; fi

soap "d:share:文档" | dec > "$TMP/doc.xml"
if [ "$(grep -c '<item id=' "$TMP/doc.xml")" -eq 0 ]; then ok "文档目录无媒体项" ""; else bad "文档目录无媒体项" "有媒体项"; fi

soap "f:share:nope-missing.mp4" > "$TMP/miss.xml"
if grep -q '<errorCode>701</errorCode>' "$TMP/miss.xml"; then ok "未知 ObjectID → 701" ""; else bad "未知 ObjectID → 701" "无 701"; fi

RES=$(grep -o '<res[^>]*>[^<]*</res>' "$TMP/share.xml" | head -1 | sed 's/.*>\(.*\)<\/res>/\1/')
chk "媒体直链 200"      "$(code "$RES")" 200
curl -s --noproxy '*' -o "$MG/media.bin" "$RES"
# 不能拿固定的 测试视频.mp4 去比：目录里第一个媒体项会随文件增减而变，
# 之前就是因为多了个 a.m4a 而误报"字节不一致"。按 URL 里的文件名反查磁盘。
SEG=$(printf '%s' "$RES" | sed 's|.*/||')
MNAME=$(printf "$(printf '%s' "$SEG" | sed 's|%|\\x|g')")
MREAL="/d/share/$MNAME"
if [ -f "$MREAL" ]; then
  A=$(md5of "$MREAL"); B=$(md5of "$MG/media.bin")
  if [ "$A" = "$B" ]; then ok "媒体字节一致" "$MNAME $A"; else bad "媒体字节一致" "$MNAME 磁盘 $A / 下载 $B"; fi
else
  bad "媒体字节一致" "URL 指向的文件不在磁盘上: $MNAME"
fi

chk "非媒体文件 403"    "$(code "$DL/media/share/%E6%96%87%E6%A1%A3/%E6%8A%A5%E4%BB%B7%E5%8D%95.txt")" 403
chk "媒体面穿越 403"    "$(code --path-as-is "$DL/media/share/../../Windows/win.ini")" 403
chk "媒体面穿越 403"    "$(code --path-as-is "$DL/media/share/..%2f..%2fWindows/win.ini")" 403
chk "根路径不列目录"    "$(code "$DL/")" 404
chk "media 不列目录"    "$(code "$DL/media/")" 404

echo
echo "========== SSDP =========="
node -e '
const dgram=require("dgram");
const s=dgram.createSocket("udp4");
let resp=null;
s.on("message",(m)=>{
  const t=m.toString();
  if(!t.startsWith("HTTP/1.1 200 OK")) return;
  if(!/MediaServer:1/.test(t)) return;
  resp=t;
});
s.bind(0,()=>{
  s.send(Buffer.from("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 2\r\nST: urn:schemas-upnp-org:device:MediaServer:1\r\n\r\n"),1900,"239.255.255.250");
});
setTimeout(()=>{
  if(!resp){ console.log("NOSDP"); process.exit(0); }
  const g=k=>{const l=resp.split("\r\n").find(x=>x.toUpperCase().startsWith(k));return l?l.substring(k.length).trim():"";};
  console.log("LOC="+g("LOCATION:"));
  console.log("ST="+g("ST:"));
  console.log("USN="+g("USN:"));
  console.log("SRV="+g("SERVER:"));
  s.close();
},4500);
' > "$TMP/ssdp.txt" 2>&1

SOUT=$(cat "$TMP/ssdp.txt")
if [ "$SOUT" = "NOSDP" ]; then
  bad "SSDP M-SEARCH 应答" "无应答"
else
  ok "SSDP M-SEARCH 应答" ""
  case "$SOUT" in *"LOC=http://"*"/rootDesc.xml"*) ok "LOCATION 指向设备描述" "$(printf '%s' "$SOUT" | grep '^LOC=' | cut -d= -f2-)" ;; *) bad "LOCATION 指向设备描述" "异常" ;; esac
  case "$SOUT" in *"ST=urn:schemas-upnp-org:device:MediaServer:1"*) ok "ST 匹配请求类型" "" ;; *) bad "ST 匹配请求类型" "不匹配" ;; esac
  case "$SOUT" in *"USN=uuid:"*) ok "USN 含 uuid" "" ;; *) bad "USN 含 uuid" "缺失" ;; esac
fi

echo
echo "-------------------------------------------"
printf '  %d 通过 / %d 失败 / 共 %d 项\n' "$PASS" "$FAIL" "$((PASS+FAIL))"
echo "-------------------------------------------"
[ "$FAIL" -eq 0 ]
