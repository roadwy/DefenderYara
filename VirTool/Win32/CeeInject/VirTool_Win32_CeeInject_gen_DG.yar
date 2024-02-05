
rule VirTool_Win32_CeeInject_gen_DG{
	meta:
		description = "VirTool:Win32/CeeInject.gen!DG,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {8a 19 88 18 88 11 8a 00 8b 4d 10 03 c2 23 c6 8a 84 05 90 01 02 ff ff 32 04 39 88 07 47 ff 4d 0c 75 90 00 } //01 00 
		$a_03_1 = {53 0f be 04 37 0f be 5c 37 01 8a 80 90 01 04 83 c6 04 8a 9b 90 01 04 c0 e0 02 c0 eb 04 0a c3 88 01 41 90 00 } //01 00 
		$a_01_2 = {4c 09 09 4d 4e 4f 4a 39 4e 2f 2f 2f 50 31 37 2f 2f 2f 4e 51 0c 02 21 0b } //01 00 
		$a_03_3 = {6a 40 68 00 30 00 00 ff 90 01 01 50 ff 90 01 01 34 ff 75 90 01 01 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}