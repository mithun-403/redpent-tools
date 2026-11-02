"""setup.py exists only to hook the CLI-tool install into the Python package install.

Metadata lives in pyproject.toml. These custom commands make `pip install .` and
`pip install -e .` ALSO install the recon CLI tools (nmap, subfinder, httpx, ...) for the
current OS — i.e. the tools are installed when the project is installed.

The hook is best-effort: it never fails the Python install, and it is skipped when
REDPENT_SKIP_TOOL_INSTALL is set (useful in CI or when building wheels).
"""
from setuptools import setup
from setuptools.command.develop import develop
from setuptools.command.install import install


def _install_tools():
    try:
        # Import lazily so a partial/parallel install can't break import.
        import os
        import sys
        sys.path.insert(0, os.path.dirname(__file__))
        from redpent_tools.installer import run_tool_install
        run_tool_install("all", best_effort=True)
    except Exception as e:  # pragma: no cover - never fail the pip install
        print(f"redpent-tools: post-install tool step skipped ({e}). "
              f"Run `redpent-tools-install` manually.")


class PostInstall(install):
    def run(self):
        install.run(self)
        _install_tools()


class PostDevelop(develop):
    def run(self):
        develop.run(self)
        _install_tools()


setup(cmdclass={"install": PostInstall, "develop": PostDevelop})
