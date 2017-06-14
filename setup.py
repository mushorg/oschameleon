from setuptools import setup

import oschameleon

setup(
    packages=["oschameleon", ],
    name=oschameleon.__title__,
    version=oschameleon.__version__,
    author='Glastopf Project',
    author_email='glaslos@gmail.com',
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        "Topic :: Security",
    ],
    package_data={
        "": ["*.txt", "*.md"],
    },
    include_package_data=True,
    long_description=open('README.rst').read(),
    url='https://github.com/glastopf/oschameleon',
    description='OS Fingerprint Obfuscation for modern Linux Kernels',
    test_suite='nose.collector',
    tests_require="nose",
    zip_safe=False,
    install_requires=open('requirements.txt').read().splitlines(),
)
