
rule MonitoringTool_AndroidOS_MonitorMinor_BB_MTB{
	meta:
		description = "MonitoringTool:AndroidOS/MonitorMinor.BB!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {21 30 35 02 1b 00 48 00 03 02 21 45 94 05 02 05 48 05 04 05 b1 50 13 05 80 ff 35 50 08 00 d9 00 00 80 d9 00 00 7f d8 00 00 01 8d 00 4f 00 03 02 d8 00 02 01 01 02 28 e5 } //1
		$a_00_1 = {21 31 35 10 1a 00 48 01 03 00 21 24 94 04 00 04 48 04 02 04 b1 41 13 04 80 ff 35 41 08 00 d9 01 01 80 d9 01 01 7f d8 01 01 01 8d 11 4f 01 03 00 d8 00 00 01 28 e6 } //1
		$a_01_2 = {64 61 6c 76 69 6b 2e 73 79 73 74 65 6d 2e 44 65 78 43 6c 61 73 73 4c 6f 61 64 65 72 } //1 dalvik.system.DexClassLoader
		$a_01_3 = {6c 6f 61 64 43 6c 61 73 73 } //1 loadClass
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}