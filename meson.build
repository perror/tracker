# Project initialization
project('tracker', 'c',
        version         : '0.1.0',
        license         : 'BSD-3-Clause',
        default_options : ['c_std=c11', 'warning_level=2']
)

# Configure config.h
conf = configuration_data()
conf.set('VERSION', meson.project_version())

# Configure default C compiler
cc = meson.get_compiler('c')
incdir = include_directories('include')

# Configure buildtype
buildtype = get_option('buildtype')

# Looking for dependencies
capstone_dep = cc.find_library('capstone', required : true)

# Set the debug flags and tests if needed
tracker_debug_cflags = []
if buildtype.startswith('debug')
  add_languages('cpp')
  cmocka_dep = dependency('cmocka', fallback : ['cmocka', 'cmocka_dep'])
  tracker_debug_cflags += ['-DDEBUG']
elif buildtype == 'release'
  tracker_debug_cflags += ['-DNDEBUG']
endif
add_project_arguments(tracker_debug_cflags, language : 'c')

# Collecting subdirs
subdir('src')
if buildtype.startswith('debug')
  subdir('tests')
endif
