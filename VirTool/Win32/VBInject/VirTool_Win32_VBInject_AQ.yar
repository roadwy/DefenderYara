
rule VirTool_Win32_VBInject_AQ{
	meta:
		description = "VirTool:Win32/VBInject.AQ,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {8b 7d 08 8a 04 18 a2 90 01 04 ff 37 e8 90 01 04 ff 35 90 01 04 8a 18 32 1d 90 01 04 ff 37 e8 90 01 04 88 18 a1 90 01 04 83 c0 01 70 15 3b 45 0c a3 90 01 04 0f 8e 90 00 } //01 00 
		$a_03_1 = {89 18 6a 01 58 66 03 45 e0 0f 80 90 01 04 89 45 e0 eb ae e8 90 01 04 56 56 56 56 50 e8 90 00 } //01 00 
		$a_03_2 = {66 8b d7 66 c1 fa 0f 8b da 33 55 ac 33 1d 90 01 04 66 3b da 7f 39 0f bf d9 3b de 72 05 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}