
rule Trojan_Win32_Azorult_PVD_MTB{
	meta:
		description = "Trojan:Win32/Azorult.PVD!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {0f b6 c8 33 d9 8b 55 08 03 55 0c 88 1a 8b 45 0c 83 e8 01 89 45 0c eb } //02 00 
		$a_01_1 = {8a 1c 3e 8b 74 24 1c 32 1c 0e 88 7c 24 33 8b 4c 24 20 88 1c 39 } //02 00 
		$a_01_2 = {8b 44 24 10 33 c6 89 44 24 10 2b e8 8b 44 24 38 d1 6c 24 1c 29 44 24 14 ff 4c 24 28 0f 85 } //00 00 
	condition:
		any of ($a_*)
 
}