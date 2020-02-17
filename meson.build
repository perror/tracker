project('tracker', 'c', 'cpp',
  version : '0.1.0',
  default_options : [
    'buildtype=release',
    'warning_level=2',
    'c_std=c11',
  ]
)

cc = meson.get_compiler('c')
incdir = include_directories('include')

capstone_dep = cc.find_library('capstone', required: true)

cxx = meson.get_compiler('cpp')

subdir('src')
subdir('tests')
