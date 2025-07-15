#
# Copyright (c) 2023-2024 NVIDIA CORPORATION & AFFILIATES, ALL RIGHTS RESERVED.
#
# This software product is a proprietary product of NVIDIA CORPORATION &
# AFFILIATES (the "Company") and all right, title, and interest in and to the
# software product, including all associated intellectual property rights, are
# and shall remain exclusively with the Company.
#
# This software product is governed by the End User License Agreement
# provided with the software product.
#

project(
	'DETECTION_AGENT',
	'C',
	'CPP',
	# Get version number from file.
	version: run_command(find_program('cat'), files('VERSION'), check: true).stdout().strip(),
	license: 'Proprietary',
	default_options: ['buildtype=debug', 'cpp_std=c++11'],
	meson_version: '>= 0.61.2',
)

host_srcs = files( 'host/pcc_core.c', 'host/detection_agent.c', 'host/main.c')

languages = ['c', 'cpp']
add_project_arguments('-D DOCA_ALLOW_EXPERIMENTAL_API', language: languages)
add_project_arguments('-D DOCA_ALLOW_DEPRECATED_API', language: languages)
add_project_arguments('-D DOCA_LOGGING_ALLOW_TRACE', language: languages)
add_project_arguments('-D DOCA_USE_LIBBSD', language: languages)
# Resolve irrelevant compiler warnings
add_project_arguments('-Wno-format-zero-length', language: languages)

device_code_build_script_name = 'build_device_code.sh'
device_code_build_script = meson.current_source_dir() / device_code_build_script_name

app_device_build_dir = meson.project_build_root() + '/' + '/device/build_dpacc'

# Command to compile the application
app_builds = find_program(device_code_build_script)

doca_dep = dependency('doca-common')
doca_lib_dir = doca_dep.get_variable(pkgconfig: 'libdir')
pcc_app_dev_src_dir = meson.project_source_root() + '/device/'

# check user option to enable TX bytes counter sampling
if get_option('enable_pcc_application_tx_counter_sampling')
	enable_tx_counter_sampling = 'true'
else
	enable_tx_counter_sampling = 'false'
endif

# check user option to enable NP RX rate update
if get_option('enable_pcc_application_np_rx_rate')
	enable_np_rx_rate = 'true'
else
	enable_np_rx_rate = 'false'
endif

# Compile DOCA PCC Reaction Point DPA program
pcc_rp_app_name = 'pcc_rp_app'
run_command(
	app_builds,
	pcc_app_dev_src_dir,
	app_device_build_dir,
	doca_lib_dir,
	pcc_rp_app_name,
	enable_tx_counter_sampling,
	enable_np_rx_rate,
	check: true,
)
pcc_rp_app = meson.get_compiler('c').find_library(pcc_rp_app_name, dirs: app_device_build_dir, static: true)

# Compile DOCA PCC Notification Point NIC Telemetry DPA program
pcc_np_nic_telemetry_app_name = 'pcc_np_nic_telemetry_app'
run_command(
	app_builds,
	pcc_app_dev_src_dir,
	app_device_build_dir,
	doca_lib_dir,
	pcc_np_nic_telemetry_app_name,
	enable_tx_counter_sampling,
	enable_np_rx_rate,
	check: true,
)
pcc_np_nic_telemetry_app = meson.get_compiler('c').find_library(pcc_np_nic_telemetry_app_name, dirs: app_device_build_dir, static: true)

dependencies = [
	dependency('libflexio'),
	dependency('doca-common'),
	dependency('doca-argp'),
	dependency('doca-pcc'),
	dependency('threads'),
	dependency('json-c'),
	dependency('libbsd'),
]

c_args = [
	'-Wno-missing-braces',
	'-Wno-missing-field-initializers',
]

# Build executable
executable(
	'detection_agent',
	host_srcs,
	c_args: c_args,
	include_directories: ['./host'],
	dependencies: [dependencies, pcc_rp_app, pcc_np_nic_telemetry_app],
	install: false,
)