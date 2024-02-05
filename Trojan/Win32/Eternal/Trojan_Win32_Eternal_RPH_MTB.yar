
rule Trojan_Win32_Eternal_RPH_MTB{
	meta:
		description = "Trojan:Win32/Eternal.RPH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 61 75 6d 31 38 31 30 } //01 00 
		$a_01_1 = {3a 25 41 4b 6b 6c 69 25 3a } //01 00 
		$a_01_2 = {3a 25 4c 68 56 61 74 46 4d 42 58 25 3a } //01 00 
		$a_01_3 = {3a 25 41 48 67 54 51 25 3a } //01 00 
		$a_01_4 = {3a 25 51 6b 4b 77 79 49 4c 6b 25 3a } //01 00 
		$a_01_5 = {3a 25 55 44 59 55 44 5a 4a 65 25 3a } //00 00 
	condition:
		any of ($a_*)
 
}