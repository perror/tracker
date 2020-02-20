# Write config.h
configure_file(input  : 'config.h.in',
	       output : 'config.h',
               configuration : conf)

# Main executable
tracker = executable('tracker',
		     ['tracker.c', 'executables.c', 'traces.c'],
		     install             : true,
		     include_directories : incdir,
		     dependencies        : capstone_dep)
