
rule VirTool_Win32_VBInject_VM{
	meta:
		description = "VirTool:Win32/VBInject.VM,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {3b cf 74 1f 66 83 39 01 75 19 0f bf f3 2b 71 14 3b 71 10 72 09 } //01 00 
		$a_01_1 = {8b 85 3c ff ff ff 89 b5 34 ff ff ff c7 85 2c ff ff ff 02 00 00 00 83 c4 1c 8b 48 14 8d 95 2c ff ff ff c1 e1 04 } //01 00 
		$a_00_2 = {5c 00 41 00 76 00 69 00 5c 00 52 00 6f 00 70 00 65 00 72 00 5c 00 6f 00 52 00 6f 00 5c 00 70 00 65 00 5c 00 72 00 6f 00 6e 00 65 00 5c 00 74 00 61 00 41 00 76 00 69 00 2e 00 6f 00 6e 00 65 00 74 00 2e 00 76 00 62 00 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}