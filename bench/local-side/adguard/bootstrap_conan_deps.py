#!/usr/bin/env python3
import os
import shutil
import subprocess
import sys
import yaml

work_dir = os.getcwd()
vpn_libs_conanfile = sys.argv[1]
nlc_url = sys.argv[2]
nlc_dir_name = "native-libs-common"
dns_libs_url = sys.argv[3]
dns_libs_dir_name = "dns-libs"
nlc_versions = []

with open(os.path.join(work_dir, vpn_libs_conanfile), "r") as file:
    for r in yaml.safe_load(file)["requirements"]:
        if r.startswith("native_libs_common"):
            nlc_versions.append(r.split('@')[0].split('/')[1])
        elif r.startswith("dns-libs"):
            dns_libs_version = r.split('@')[0].split('/')[1]

dns_libs_dir = os.path.join(work_dir, dns_libs_dir_name)
subprocess.run(["git", "clone", dns_libs_url, dns_libs_dir], check=True)
os.chdir(dns_libs_dir)
with open("conanfile.py", "r") as file:
    for line in file.readlines():
        line = line.strip().removeprefix("self.requires(\"")
        if line.startswith("native_libs_common"):
            nlc_versions.append(line.split('@')[0].split('/')[1])
subprocess.run([os.path.join("scripts", "export_conan.py"), dns_libs_version], check=True)
shutil.rmtree(dns_libs_dir)

os.chdir(work_dir)
nlc_dir = os.path.join(work_dir, nlc_dir_name)
subprocess.run(["git", "clone", nlc_url, nlc_dir], check=True)
os.chdir(nlc_dir)

# Reduce the chances of missing a necessary dependency exported with NLC
# by exporting all recipes from all versions of NLC, starting with the minimum
# necessary.
min_nlc_version = min(nlc_versions)
with open("conandata.yml", "r") as file:
    items = yaml.safe_load(file)["commit_hash"]
    for v in [k for k in items.keys() if k >= min_nlc_version]:
        subprocess.run(["git", "checkout", "master"], check=True)
        subprocess.run([os.path.join(nlc_dir, "scripts", "export_conan.py"), v], check=True)

shutil.rmtree(nlc_dir)
