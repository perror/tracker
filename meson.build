# Set the project
project('tracker', 'c',
  version : '0.1.0',
  default_options : [
    'buildtype=debug',
    'warning_level=2',
    'c_std=c11',
  ]
)

# Configure default C compiler
cc = meson.get_compiler('c')
incdir = include_directories('include')

# Configure buildtype
buildtype = get_option('buildtype')

# Looking for dependencies
capstone_dep = cc.find_library('capstone', required: true)

# Set the debug flags if needed
tracker_debug_cflags = []
if buildtype.startswith('debug')
  tracker_debug_cflags += ['-DDEBUG']
  add_languages('cpp')
  cmocka_dep = dependency('cmocka', fallback : ['cmocka', 'cmocka_dep'])
elif buildtype == 'release'
  tracker_debug_cflags += ['-DNDEBUG']
endif

add_project_arguments(tracker_debug_cflags, language: 'c')


subdir('src')
if buildtype.startswith('debug')
  subdir('tests')
endif
