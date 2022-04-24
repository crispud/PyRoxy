from setuptools import setup

setup(name='PyRoxy',
      version="1.11",
      packages=['PyRoxy', 'PyRoxy.Tools', 'PyRoxy.Exceptions'],
      url='https://github.com/MHProDev/PyRoxy',
      license='MIT',
      author="MH_ProDev",
      install_requires=[
          "requests>=2.27.1", "yarl>=1.7.2", "pysocks>=1.7.1"
      ],
      include_package_data=True,
      package_data={
      })
