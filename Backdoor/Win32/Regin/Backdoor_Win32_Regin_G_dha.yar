
rule Backdoor_Win32_Regin_G_dha{
	meta:
		description = "Backdoor:Win32/Regin.G!dha,SIGNATURE_TYPE_PEHSTR_EXT,64 00 64 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d f4 01 00 00 75 07 68 90 01 04 eb 21 3d 58 02 00 00 75 07 68 90 01 04 eb 13 3d bc 02 00 00 75 07 68 90 01 04 eb 05 90 00 } //01 00 
		$a_01_1 = {3c 20 7c 04 3c 7f 7c 08 3c 09 } //01 00 
		$a_01_2 = {00 70 77 20 63 68 61 6e 67 65 64 3a 00 } //01 00 
		$a_01_3 = {20 66 69 6c 65 73 70 65 63 7c 21 73 79 73 21 } //00 00 
		$a_00_4 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}