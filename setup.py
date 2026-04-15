from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="pol-decoder",
    version="2.1.1",
    author="reno",
    description="Prometheus Lua Obfuscator Deobfuscator with VM decoding",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/renovenom/Pol-decoder",
    py_modules=["prometheus_deobf"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.6",
    install_requires=[
        "colorama>=0.4.6",
    ],
    entry_points={
        "console_scripts": [
            "pol-decoder=prometheus_deobf:main",
        ],
    },
)