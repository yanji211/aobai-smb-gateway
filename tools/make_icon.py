# 生成「熬拜共享家」程序图标：宣纸白圆角底 + 墨黑 logo + 朱砂红共享徽章。
# （取代旧的 tools/icon_gen.go——那个手绘的抽象图标已弃用，logo 来自
#   C://Users//example-user//Desktop//desk88//UI设计//logo.png，即「熬拜」水墨书法标。）
#
# 为什么手绘徽章而不是直接拼图：logo 本身没有"共享"语义，加一枚朱砂红圆章
# （三节点连线 = 分享/共享）后才能和熬拜其它程序（纯书法 logo）一眼区分。
# 输出：
#   internal/tray/fsgw.ico         托盘 + exe 资源图标（16/24/32/48/64/128/256）
#   internal/tray/preview.png      预览大图
#
# 用法：python tools/make_icon.py [logo.png]
import os
import sys

from PIL import Image, ImageDraw

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# 品牌色（与 UI 稿一致）
PAPER = (250, 246, 239, 255)      # 宣纸白
INK = (26, 26, 26, 255)           # 墨黑
CINNABAR = (198, 46, 30, 255)     # 朱砂红
EDGE = (208, 192, 168, 255)       # 淡墨边

S = 1024  # 先按 1024 渲染，再缩到各尺寸


def load_logo(path):
    logo = Image.open(path).convert("RGBA")
    # 只保留墨色像素：原图是透明底黑字，保险起见把近透明的像素压成全透明，
    # 免得缩放时出现灰边。
    px = logo.load()
    w, h = logo.size
    for y in range(h):
        for x in range(w):
            r, g, b, a = px[x, y]
            if a < 24:
                px[x, y] = (0, 0, 0, 0)
            else:
                px[x, y] = (r, g, b, a)
    return logo.crop(logo.getbbox())


def draw_share_badge(d, cx, cy, r):
    """朱砂红圆章 + 白色三节点共享符号。"""
    # 外圈留一圈纸色，形成"嵌入"的层次感
    d.ellipse([cx - r - 16, cy - r - 16, cx + r + 16, cy + r + 16], fill=PAPER)
    d.ellipse([cx - r, cy - r, cx + r, cy + r], fill=CINNABAR)

    # 三节点位置（标准 share 图标布局：左中 + 右上 + 右下）
    dotr = r * 0.20
    left = (cx - r * 0.42, cy)
    ur = (cx + r * 0.40, cy - r * 0.40)
    lr = (cx + r * 0.40, cy + r * 0.40)

    line_w = int(r * 0.14)
    for a, b in ((left, ur), (left, lr)):
        d.line([a, b], fill=PAPER, width=line_w)
    for p in (left, ur, lr):
        d.ellipse([p[0] - dotr, p[1] - dotr, p[0] + dotr, p[1] + dotr], fill=PAPER)


def render(logo):
    canvas = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    d = ImageDraw.Draw(canvas)

    # 圆角方底：Windows 图标习惯方形，圆角避免在任务栏显得生硬
    d.rounded_rectangle([36, 36, S - 36, S - 36], radius=190, fill=PAPER,
                        outline=EDGE, width=7)

    # logo 缩到 720 宽，居中偏左上，给右下角的徽章让位
    target_w = 720
    scale = target_w / logo.width
    lw, lh = target_w, int(logo.height * scale)
    lg = logo.resize((lw, lh), Image.LANCZOS)
    canvas.alpha_composite(lg, ((S - lw) // 2 - 55, (S - lh) // 2 - 105))

    draw_share_badge(d, 770, 776, 182)
    return canvas


def main():
    src = sys.argv[1] if len(sys.argv) > 1 else r"D:\share\UI设计\logo.png"
    logo = load_logo(src)
    big = render(logo)

    out_ico = os.path.join(ROOT, "internal", "tray", "fsgw.ico")
    out_prev = os.path.join(ROOT, "internal", "tray", "preview.png")
    big.save(out_prev)

    sizes = [16, 24, 32, 48, 64, 128, 256]
    # 小尺寸单独渲染（先缩 logo 再画，线条才不糊），16/24 适当放大徽章占比
    frames = []
    for s in sizes:
        if s <= 32:
            small = Image.new("RGBA", (S, S), (0, 0, 0, 0))
            ds = ImageDraw.Draw(small)
            ds.rounded_rectangle([36, 36, S - 36, S - 36], radius=190, fill=PAPER,
                                 outline=EDGE, width=10)
            tw = 780
            sc = tw / logo.width
            lg = logo.resize((tw, int(logo.height * sc)), Image.LANCZOS)
            small.alpha_composite(lg, ((S - tw) // 2 - 65, (S - int(logo.height * sc)) // 2 - 125))
            draw_share_badge(ds, 772, 774, 200)
            frames.append(small.resize((s, s), Image.LANCZOS))
        else:
            frames.append(big.resize((s, s), Image.LANCZOS))

    frames[-1].save(out_ico, format="ICO",
                    sizes=[(f.width, f.height) for f in frames],
                    append_images=frames[:-1])
    print("wrote", out_ico, os.path.getsize(out_ico), "bytes")
    print("wrote", out_prev, os.path.getsize(out_prev), "bytes")


if __name__ == "__main__":
    main()
