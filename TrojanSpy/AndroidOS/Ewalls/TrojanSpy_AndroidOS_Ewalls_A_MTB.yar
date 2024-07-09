
rule TrojanSpy_AndroidOS_Ewalls_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Ewalls.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_03_0 = {61 70 69 2e 62 69 74 2e 6c 79 2f 73 68 6f 72 74 65 6e 3f 76 65 72 73 69 6f 6e 3d [0-06] 26 6c 6f 67 69 6e 3d 65 77 61 6c 6c 70 61 70 65 72 26 61 70 69 4b 65 79 3d [0-40] 26 6c 6f 6e 67 55 72 6c } //1
		$a_01_1 = {73 65 6e 64 44 65 76 69 63 65 49 6e 66 6f 73 } //1 sendDeviceInfos
		$a_01_2 = {2f 6c 6f 67 2f 61 63 74 69 6f 6e 5f 6c 6f 67 3f 74 79 70 65 65 } //1 /log/action_log?typee
		$a_01_3 = {2f 6c 6f 67 2f 64 65 76 69 63 65 5f 69 6e 66 6f 3f } //1 /log/device_info?
		$a_01_4 = {77 70 73 2e 61 70 70 73 63 6f 6c 6f 72 2e 6e 65 74 } //1 wps.appscolor.net
		$a_01_5 = {6c 6f 67 2e 79 73 6c 65 72 2e 63 6f 6d } //1 log.ysler.com
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}