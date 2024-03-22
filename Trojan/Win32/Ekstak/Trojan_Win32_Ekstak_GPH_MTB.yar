
rule Trojan_Win32_Ekstak_GPH_MTB{
	meta:
		description = "Trojan:Win32/Ekstak.GPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 04 00 "
		
	strings :
		$a_03_0 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 90 01 03 00 90 01 03 00 00 62 0a 00 3c 87 da e7 bf 90 00 } //04 00 
		$a_03_1 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 90 01 03 00 90 01 03 00 00 68 0a 00 b8 27 8e cd 33 90 00 } //04 00 
		$a_03_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 90 01 03 00 90 01 03 00 00 68 0a 00 3b f3 a8 9a aa 90 00 } //04 00 
		$a_03_3 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 90 01 03 00 90 01 03 00 00 62 0a 00 3c 87 da e7 79 90 00 } //04 00 
		$a_03_4 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 90 01 03 00 90 01 03 00 00 68 0a 00 b8 27 8e cd c4 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}