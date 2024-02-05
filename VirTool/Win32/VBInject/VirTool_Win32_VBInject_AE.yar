
rule VirTool_Win32_VBInject_AE{
	meta:
		description = "VirTool:Win32/VBInject.AE,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {f5 00 00 00 00 cc 1c 40 02 00 0e 6c 38 ff ec f4 04 eb b6 e8 71 34 ff 00 19 f5 00 00 00 00 04 2c ff 6c 34 ff f5 01 00 00 00 ae fe 64 1c ff 3d 02 00 28 f5 01 00 00 00 6c 2c ff 6c 3c ff 9e 0b 02 00 04 00 23 18 ff 1b 03 00 f5 00 00 00 00 fe fd fc 52 2f 18 ff 1c 31 02 00 0e 6c 2c ff 6c 3c ff 9e fb fe 31 78 ff 00 02 00 0a 04 2c ff 66 1c ff fb 01 1e 42 02 00 02 00 02 00 00 14 } //01 00 
		$a_01_1 = {73 00 76 00 63 00 68 00 6f 00 73 00 74 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}