
rule MonitoringTool_MacOS_RealtimeSpy_B_MTB{
	meta:
		description = "MonitoringTool:MacOS/RealtimeSpy.B!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 55 73 65 72 73 2f 73 70 79 74 65 63 68 2f 44 65 73 6b 74 6f 70 2f 73 6f 75 72 63 65 2f 52 65 61 6c 74 69 6d 65 2d 53 70 79 2f } //1 /Users/spytech/Desktop/source/Realtime-Spy/
		$a_01_1 = {52 65 61 6c 74 69 6d 65 2d 53 70 79 2f 72 65 6c 61 75 6e 63 68 2f 6d 61 69 6e 2e 6d } //1 Realtime-Spy/relaunch/main.m
		$a_01_2 = {52 65 61 6c 74 69 6d 65 2d 53 70 79 2e 62 75 69 6c 64 2f 44 65 62 75 67 2f 72 65 6c 61 75 6e 63 68 2e 62 75 69 6c 64 } //1 Realtime-Spy.build/Debug/relaunch.build
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}