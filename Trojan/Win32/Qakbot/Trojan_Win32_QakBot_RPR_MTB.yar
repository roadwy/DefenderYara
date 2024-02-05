
rule Trojan_Win32_QakBot_RPR_MTB{
	meta:
		description = "Trojan:Win32/QakBot.RPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 30 00 00 8b 4d 0c 6b 11 03 52 6a 00 ff 15 } //01 00 
		$a_01_1 = {8b 55 dc 83 c2 01 89 55 dc 8b 45 f0 83 e8 01 39 45 dc 7d 1a 8b 4d c4 03 4d d4 8b 55 dc 8a 44 15 d8 88 01 8b 4d d4 83 c1 01 89 4d d4 eb d2 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_QakBot_RPR_MTB_2{
	meta:
		description = "Trojan:Win32/QakBot.RPR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {41 46 64 39 72 48 4d 31 61 } //01 00 
		$a_01_1 = {42 61 74 61 4d 36 6f 68 6f 6f } //01 00 
		$a_01_2 = {41 78 69 6f 39 50 35 57 } //01 00 
		$a_01_3 = {43 4e 6e 45 50 78 } //01 00 
		$a_01_4 = {43 5a 78 44 51 6b 56 } //01 00 
		$a_01_5 = {44 59 63 66 43 42 78 53 } //00 00 
	condition:
		any of ($a_*)
 
}