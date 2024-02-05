
rule VirTool_Win32_VBInject_gen_IU{
	meta:
		description = "VirTool:Win32/VBInject.gen!IU,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {4e 4f 44 45 4d 47 52 4c 69 62 43 74 6c 2e 54 61 73 6b 53 79 6d 62 6f 6c } //01 00 
		$a_03_1 = {66 83 39 01 75 90 01 01 8b 41 14 8b 51 10 f7 d8 3b c2 89 90 03 04 04 45 90 01 01 85 90 01 04 72 90 14 8b 49 0c 03 c8 51 ff d7 8d 90 03 04 04 55 90 01 01 95 90 01 04 8b f8 52 ff 15 90 01 04 8b 90 03 04 04 45 90 01 01 85 90 01 04 56 56 57 50 53 e8 90 01 02 ff ff ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}