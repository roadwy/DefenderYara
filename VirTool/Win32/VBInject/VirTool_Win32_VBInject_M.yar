
rule VirTool_Win32_VBInject_M{
	meta:
		description = "VirTool:Win32/VBInject.M,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c 00 60 e8 00 00 00 00 58 2d 62 fd ff ff 8b 30 03 f0 2b c0 8b fe 66 ad c1 e0 0c 8b c8 50 ad 2b c8 03 f1 8b c8 57 51 49 8a 44 39 06 74 05 } //01 00 
		$a_01_1 = {46 00 3a 88 1c 40 04 d0 c4 00 45 00 50 02 00 61 00 63 00 6b 44 a0 8c 10 e9 53 c6 c5 63 2e 00 76 0d 00 62 00 70 } //00 00 
	condition:
		any of ($a_*)
 
}