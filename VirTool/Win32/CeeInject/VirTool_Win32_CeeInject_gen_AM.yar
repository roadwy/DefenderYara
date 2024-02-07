
rule VirTool_Win32_CeeInject_gen_AM{
	meta:
		description = "VirTool:Win32/CeeInject.gen!AM,SIGNATURE_TYPE_PEHSTR_EXT,15 00 14 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6c 78 76 63 6a 76 68 64 6c 00 } //01 00  硬捶癪摨l
		$a_01_1 = {66 61 67 77 6d 70 00 00 6e 6a 77 6f 69 75 69 00 6c 77 72 77 6c 6a 6b 6d 6a 00 } //0a 00 
		$a_01_2 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 00 53 62 69 65 44 6c 6c 2e 64 6c 6c } //0a 00 
		$a_01_3 = {8d 84 9d fc fb ff ff 89 0f 0f b6 ca 83 c7 04 39 75 fc 89 08 7c bc } //00 00 
	condition:
		any of ($a_*)
 
}