from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="topay01",
    version="0.0.1",
    author="TOPAY Foundation",
    author_email="info@topay.foundation",
    description="A lightweight, high-security cryptographic library optimized for mobile processors with quantum-resistant algorithms",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/MdShahriya/TOPAY-01",
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
    ],
    python_requires=">=3.7",
)