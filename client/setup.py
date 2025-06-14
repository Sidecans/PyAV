from setuptools import setup

setup(
  name = "PvAV",
  version = "1.0",
  py_modules=['client'],
  install_requires=[
    'requests',
    'colorama',
    'flask'
  ],
  entry_points={
    'console_scripts': [
      'PvAV = client:cli',
    ]
  },
  author="Sidecans",
  description="Python based Antivirus",
  classifiers= [
    "Programming Language :: Python :: 3"
  ]
)