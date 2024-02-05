
rule Trojan_Win32_Macultum_gen_A{
	meta:
		description = "Trojan:Win32/Macultum.gen!A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {eb 4e 6a 00 6a 04 b9 90 01 04 e8 90 01 04 b8 01 00 00 00 85 c0 74 2d e8 90 01 04 68 30 75 00 00 90 00 } //02 00 
		$a_01_1 = {74 06 83 7d 08 01 75 0c 8b 55 dc c7 42 44 00 00 00 00 eb 0f 8b 45 dc } //01 00 
		$a_01_2 = {58 3a 5c 70 72 6f 6a 65 63 74 73 5c 70 78 5c 6d 6f 6e 69 74 6f 72 5c 4d 6f 6e 69 74 6f 72 2e 70 64 62 } //01 00 
		$a_01_3 = {4d 75 74 75 61 6c 20 69 6e 73 74 61 6c 6c 20 7c 20 72 65 6d 6f 76 65 } //00 00 
	condition:
		any of ($a_*)
 
}