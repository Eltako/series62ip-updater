from setuptools import setup, find_namespace_packages

setup(name='eltako-update',
      version='1.0.0',
      description='Eltako Series 62 IP update tools',
      long_description='Scripts and modules to update Eltako Series 62 IP devices.',
      url='https://github.com/Eltako/series62ip-updater',
      author='Eltako GmbH',
      author_email='technical-support@eltako.de',
      license='Undecided',
      packages=find_namespace_packages(include=['eltako.update.*']),
      install_requires=[
            "requests",
            "pyopenssl",
            "cryptography",
            "typing",
            "urllib3",
            "six",
            "argparse",
            "typeguard",
            "tqdm"
      ],
      entry_points = {
            'console_scripts': ['eltako-update=eltako.update.cmdline:main'],
      },
      zip_safe=False)
