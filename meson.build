project('hotp-verification', 'c',
  version : '1.4.0',
)
lusb = dependency('libusb-1.0')
version_array = meson.project_version().split('.')
version_major = version_array[0].to_int()
version_minor = version_array[1].to_int()
version_data = configuration_data()
version_data.set('PROJECT_VERSION_MAJOR', version_major)
version_data.set('PROJECT_VERSION_MINOR', version_minor)
# We don't want to substitute it by noop
version_data.set('GIT_VERSION_PLACEHOLDER', '@VCS_TAG@')
version_cc_in = configure_file(
  input : 'src/version.c.in',
  output : 'version.c.in',
  configuration : version_data,
)
version_cc = vcs_tag(
  input : version_cc_in,
  output : 'version.c',
  fallback : 'v@0@'.format(meson.project_version()),
)


src = [
'src/crc32.c',
'src/device.c',
'src/operations.c',
'src/dev_commands.c',
'src/base32.c',
'src/random_data.c',
'src/min.c',
'src/utils.c',
version_cc,
'src/return_codes.c',
'src/main.c',
'src/tlv.c',
'src/ccid.c',
'src/operations_ccid.c',
'hidapi/libusb/hid.c'
]


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
include_directories('src/'),
include_directories('hidapi/hidapi'),
])

name = 'hotp-verification'
executable(name, src, dependencies : lusb, include_directories: incdir, c_args: common_flags)
