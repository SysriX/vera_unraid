"""Copies the shared UI files into plugin_mira/ (run after changing app/web/*.js|css).

Then sign + pack:  py tools/mira_plugin.py pack plugin_mira --key <path>/sysrix.key --out dist
and publish:       py tools/mira_plugin.py publish dist/vera-<version>.zip --url <PIA> --token pia_…
"""
import json
import os
import shutil

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DST = os.path.join(ROOT, "plugin_mira")
for name in ("wireguard.js", "wireguard.css", "vera-views.js", "icon.svg"):
    shutil.copyfile(os.path.join(ROOT, "app", "web", name), os.path.join(DST, name))

version = next(line.split('"')[1] for line in open(os.path.join(ROOT, "app", "core.py"), encoding="utf-8")
               if line.startswith("VERSION ="))
p = os.path.join(DST, "plugin.json")
m = json.load(open(p, encoding="utf-8"))
m["version"] = version
with open(p, "w", encoding="utf-8", newline="\n") as f:
    json.dump(m, f, ensure_ascii=False, indent=2)
    f.write("\n")
print("plugin_mira aktualisiert, Version", version, "– jetzt signieren: py tools/mira_plugin.py pack plugin_mira --key …")
