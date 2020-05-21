project('hotp-verification', 'c',
  version : '1.2.0',
)
lusb = dependency('libusb-1.0')

src = [
'crc32.c',
'device.c',
'operations.c',
'dev_commands.c',
'base32.c',
'random_data.c',
'min.c',
'version.c',
'return_codes.c',
'main.c',
'hidapi/libusb/hid.c'
]

version_array = meson.project_version().split('.')
version_major = version_array[0].to_int()
version_minor = version_array[1].to_int()
version_data = configuration_data()
version_data.set('PROJECT_VERSION_MAJOR', version_major)
version_data.set('PROJECT_VERSION_MINOR', version_minor)
# We don't want to substitute it by noop
version_data.set('GIT_VERSION_PLACEHOLDER', '@VCS_TAG@')
version_cc_in = configure_file(
  input : 'version.c.in',
  output : 'version.c.in',
  configuration : version_data,
)
version_cc = vcs_tag(
  input : version_cc_in,
  output : 'version.c',
  fallback : 'v@0@'.format(meson.project_version()),
)

common_flags = [
'-DNK_REMOVE_PTHREAD',
'-fdebug-prefix-map=$PWD=heads',
'-gno-record-gcc-switches',
'-DNDEBUG',
'-fno-guess-branch-probability',
'-Wdate-time',
'-frandom-seed=0x42',
'-O0',
]

incdir = ([
include_directories('.'),
include_directories('hidapi/hidapi'),
])

name1 = 'nitrokey-hotp-verification'
name2 = 'libremkey-hotp-verification'
executable(name1, src, dependencies : lusb, include_directories: incdir, c_args: common_flags)
executable(name2, src, dependencies : lusb, include_directories: incdir, c_args: common_flags)