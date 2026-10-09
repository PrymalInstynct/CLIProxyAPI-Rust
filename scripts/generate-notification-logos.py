#!/usr/bin/env python3
"""Generate Discord PNGs from the dashboard's canonical provider SVG symbols.

Development tool only. Requires rsvg-convert; proxy builds need no renderer.
"""
import copy
import pathlib
import subprocess
import xml.etree.ElementTree as ET


def main():
    root = pathlib.Path(__file__).resolve().parents[1]
    assets = root / "src/notifications/assets"
    source = (root / "ui/logos.svg").read_text()
    attribution = source[:source.index("-->") + 3]
    namespace = "http://www.w3.org/2000/svg"
    ET.register_namespace("", namespace)
    symbols = ET.fromstring(source)
    assets.mkdir(parents=True, exist_ok=True)
    for provider, title, background in [
        ("claude", "Claude", "#FAF9F5"),
        ("codex", "ChatGPT / Codex", "#FFFFFF"),
    ]:
        symbol = next(x for x in symbols.iter() if x.attrib.get("id") == "logo-" + provider)
        svg = ET.Element("{" + namespace + "}svg", {
            "viewBox": "0 0 32 32", "width": "128", "height": "128",
            "role": "img", "aria-label": title,
        })
        ET.SubElement(svg, "{" + namespace + "}rect", {
            "width": "32", "height": "32", "rx": "7", "fill": background,
        })
        group = ET.SubElement(svg, "{" + namespace + "}g", {
            "transform": "translate(4 4)", "color": "#111111",
        })
        for child in symbol:
            group.append(copy.deepcopy(child))
        path = assets / (provider + ".svg")
        path.write_text(attribution + "\n" + ET.tostring(svg, encoding="unicode") + "\n")
        subprocess.run([
            "rsvg-convert", "-w", "128", "-h", "128", "-o",
            str(assets / (provider + ".png")), str(path),
        ], check=True)


if __name__ == "__main__":
    main()
