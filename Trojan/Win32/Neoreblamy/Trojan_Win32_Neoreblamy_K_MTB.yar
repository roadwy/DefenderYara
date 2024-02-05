
rule Trojan_Win32_Neoreblamy_K_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 c0 40 c1 e0 00 0f b6 44 05 90 01 01 83 c8 90 01 01 33 c9 41 c1 e1 00 0f b6 4c 0d 90 01 01 83 e1 90 01 01 2b c1 33 c9 41 6b c9 00 0f b6 4c 0d 90 01 01 66 89 44 4d 90 00 } //01 00 
		$a_81_1 = {49 20 62 65 63 6f 6d 65 20 74 68 65 20 67 75 79 } //01 00 
		$a_81_2 = {4f 68 2c 20 6d 79 20 6b 65 79 62 6f 61 72 64 } //00 00 
	condition:
		any of ($a_*)
 
}