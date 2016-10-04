from setuptools import setup

version = open("VERSION", "rb").read().strip().decode("ascii")

setup(
    name="pygost",
    version=version,
    description="Pure Python GOST cryptographic functions library",
    author="Sergey Matveev",
    author_email="stargrave@stargrave.org",
    url="http://www.cypherpunks.ru/pygost/",
    license="GPLv3+",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
        "Natural Language :: English",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    packages=["pygost", "supplementary"],
    package_dir={"supplementary": "."},
    package_data={
        "pygost": ["stubs/**/*.pyi"],
        "supplementary": [
            "AUTHORS",
            "COPYING",
            "INSTALL",
            "NEWS",
            "PUBKEY.asc",
            "README",
            "VERSION",
        ],
    },
)
