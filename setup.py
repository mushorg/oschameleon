from setuptools import setup, find_packages

import oschameleon

setup(
    name=oschameleon.__title__,
    version=oschameleon.__version__,
    author='Glastopf Project',
    author_email='glaslos@gmail.com',
    url='https://github.com/glastopf/oschameleon',
    description='OS Fingerprint Obfuscation for modern Linux Kernels',
    packages=find_packages(exclude=["*.pyc", ]),
    zip_safe=False,
    install_requires=open('requirements.txt').read().splitlines(),
)