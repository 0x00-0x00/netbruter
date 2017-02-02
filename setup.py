from setuptools import setup

setup(name='netbruter',
      version='0.1.4',
      description='A http-post bruteforcer capable of conducting attacks with Tor network',
      url='https://github.com/0x00-0x00/netbruter.git',
      author='zc00l',
      author_email='andre.marques@fatec.sp.gov.br',
      license='MIT',
      packages=['netbruter'],
      package_dir={"netbruter": "src"},
      package_data={
          "netbruter": ["src/*"],
      },

      data_files=[
          ('netbruter', ['src/agent_list.json']),
      ],

      scripts=['bin/netbruter'],
      zip_safe=False)
