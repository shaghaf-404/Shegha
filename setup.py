from setuptools import setup, find_packages

setup(
    name="shegha",
    version="1.0",
    packages=find_packages(),
    py_modules=["shegha_cli"],
    install_requires=[],
    entry_points={
        "console_scripts": [
            "shegha=shegha_cli:main",
        ],
    },
)