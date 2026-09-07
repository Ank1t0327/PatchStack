from setuptools import setup, find_packages

setup(
    name="patchstack",
    version="0.1.0",
    description="Web Application Security Assessment Platform",
    author="PatchStack Security Team",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "flask>=3.0.0",
        "requests>=2.31.0",
        "pyyaml>=6.0.1",
        "rich>=13.7.0",
    ],
    entry_points={
        "console_scripts": [
            "patchstack=patchstack.cli:main",
        ],
    },
)
