from setuptools import setup, find_packages

setup(
    name='shellDev',
    version='1.3',
    packages=find_packages(),
    install_requires=[
        "pypiwin32"
    ],
    entry_points={
        "console_scripts": [
            "shell-dev = shell_dev.__main__:main"
        ]
    },
    url='https://github.com/aaaddress1/shellDev.py',
    license='GNU General Public License v3.0',
    author='Sheng-Hao Ma',
    author_email='aaaddress1@chroot.org',
    description=''
)
