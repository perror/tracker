tests = {
	  'traces': false
	}

foreach name, should_fail: tests
  object_file = tracker.extract_objects('@0@.c'.format(name))
  exe = executable(name, 'test_@0@.c'.format(name),
		   include_directories : incdir,
		   objects : object_file,
		   dependencies : cmocka_dep)
  test(name, exe, should_fail : should_fail)
endforeach

# Testing executables module
#executables_object = tracker.extract_objects('executables.c')

# Testing full tracker program
subdir('samples')
