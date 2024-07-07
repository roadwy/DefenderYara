
rule Trojan_Win32_Fareit_AE_MTB{
	meta:
		description = "Trojan:Win32/Fareit.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f 7e da 3d 90 02 35 90 13 90 02 15 46 90 02 15 8b 17 90 02 15 0f 6e fe 90 02 15 90 18 0f 6e da 90 02 15 0f ef df 90 02 15 c3 90 00 } //3
	condition:
		((#a_03_0  & 1)*3) >=1
 
}
rule Trojan_Win32_Fareit_AE_MTB_2{
	meta:
		description = "Trojan:Win32/Fareit.AE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_03_0 = {0f 7e da 85 90 02 35 90 13 90 02 15 46 90 02 15 8b 17 90 02 15 0f 6e fe 90 02 15 90 18 0f 6e da 90 02 15 0f ef df 90 02 15 c3 90 00 } //3
		$a_03_1 = {0f 7e da 66 90 02 35 90 13 90 02 15 46 90 02 15 8b 17 90 02 15 0f 6e fe 90 02 15 90 18 0f 6e da 90 02 15 0f ef df 90 02 15 c3 90 00 } //3
		$a_03_2 = {0f 7e da 81 90 02 35 90 13 90 02 15 46 90 02 15 8b 17 90 02 15 0f 6e fe 90 02 15 90 18 0f 6e da 90 02 15 0f ef df 90 02 15 c3 90 00 } //3
		$a_03_3 = {0f 7e da 3d 90 02 25 90 13 90 02 15 46 90 02 15 8b 17 90 02 15 0f 6e fe 90 02 15 90 18 0f 6e da 90 02 15 0f ef df 90 02 15 c3 90 00 } //3
		$a_03_4 = {0f 7e da 83 90 02 35 90 13 90 02 15 46 90 02 15 8b 17 90 02 15 0f 6e fe 90 02 15 90 18 0f 6e da 90 02 15 0f ef df 90 02 15 c3 90 00 } //3
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_03_2  & 1)*3+(#a_03_3  & 1)*3+(#a_03_4  & 1)*3) >=3
 
}