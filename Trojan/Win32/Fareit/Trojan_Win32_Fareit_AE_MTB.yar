
rule Trojan_Win32_Fareit_AE_MTB{
	meta:
		description = "Trojan:Win32/Fareit.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 7e da 3d [0-35] 90 13 [0-15] 46 [0-15] 8b 17 [0-15] 0f 6e fe [0-15] 90 18 0f 6e da [0-15] 0f ef df [0-15] c3 } //3
	condition:
		((#a_03_0  & 1)*3) >=1
 
}
rule Trojan_Win32_Fareit_AE_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_03_0 = {0f 7e da 85 [0-35] 90 13 [0-15] 46 [0-15] 8b 17 [0-15] 0f 6e fe [0-15] 90 18 0f 6e da [0-15] 0f ef df [0-15] c3 } //3
		$a_03_1 = {0f 7e da 66 [0-35] 90 13 [0-15] 46 [0-15] 8b 17 [0-15] 0f 6e fe [0-15] 90 18 0f 6e da [0-15] 0f ef df [0-15] c3 } //3
		$a_03_2 = {0f 7e da 81 [0-35] 90 13 [0-15] 46 [0-15] 8b 17 [0-15] 0f 6e fe [0-15] 90 18 0f 6e da [0-15] 0f ef df [0-15] c3 } //3
		$a_03_3 = {0f 7e da 3d [0-25] 90 13 [0-15] 46 [0-15] 8b 17 [0-15] 0f 6e fe [0-15] 90 18 0f 6e da [0-15] 0f ef df [0-15] c3 } //3
		$a_03_4 = {0f 7e da 83 [0-35] 90 13 [0-15] 46 [0-15] 8b 17 [0-15] 0f 6e fe [0-15] 90 18 0f 6e da [0-15] 0f ef df [0-15] c3 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_03_2  & 1)*3+(#a_03_3  & 1)*3+(#a_03_4  & 1)*3) >=3
 
}