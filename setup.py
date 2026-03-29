from setuptools import setup, find_packages

setup(
    name="traffic",
    version="0.1",
    packages=find_packages(),
    py_modules=["cli"],

    entry_points={
        "console_scripts": [
            "traffic=cli:main",
        ],
    },
)