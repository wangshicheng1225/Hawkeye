.PHONY: switch switch-p4 switch-ctrl clean


switch: switch-p4 switch-ctrl

switch-p4: switch/hawkeye.p4 switch/headers.p4 switch/parsers.p4 config.h
	$(SDE)/p4_build.sh $<

switch-ctrl: ctrl/ctrl.c ctrl/headers.h ctrl/switch_config.h config.h
	gcc -I$$SDE_INSTALL/include -g -O2 -std=gnu11  -L/usr/local/lib -L$$SDE_INSTALL/lib \
		$< -o contrl \
		-ldriver -lbfsys -lbfutils -lbf_switchd_lib -lm -lpthread  \




clean:
	-rm -f contrl bf_drivers.log* zlog-cfg-cur

# .DEFAULT_GOAL :=
