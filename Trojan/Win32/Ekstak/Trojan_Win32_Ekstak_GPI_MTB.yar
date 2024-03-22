
rule Trojan_Win32_Ekstak_GPI_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 04 00 "
		
	strings :
		$a_03_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 90 01 03 00 90 01 03 00 00 68 0a 00 b8 27 8e cd 33 90 00 } //04 00 
		$a_03_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 90 01 03 00 90 01 03 00 00 68 0a 00 b8 27 8e cd 57 90 00 } //04 00 
		$a_03_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 90 01 03 00 90 01 03 00 00 68 0a 00 3b f3 a8 9a 47 90 00 } //04 00 
		$a_03_3 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 90 01 03 00 90 01 03 00 00 62 0a 00 3c 87 da e7 29 90 00 } //04 00 
		$a_03_4 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 90 01 03 00 90 01 03 00 00 c4 0a 00 7d ab dd 6b 84 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}