
rule Trojan_Win32_QakBot_AN_MTB{
	meta:
		description = "Trojan:Win32/QakBot.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //02 00 
		$a_01_1 = {49 36 48 45 57 68 44 30 79 } //02 00 
		$a_01_2 = {49 67 31 6d 5a 44 64 54 67 4e 35 } //02 00 
		$a_01_3 = {4a 61 61 44 52 75 47 6f 37 6e 75 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_QakBot_AN_MTB_2{
	meta:
		description = "Trojan:Win32/QakBot.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 48 6a 68 4b 4e 38 6a 31 } //01 00 
		$a_01_1 = {44 61 74 4a 45 74 41 43 41 4b 57 } //01 00 
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00 
		$a_01_3 = {45 39 32 31 79 56 67 58 54 30 4a } //01 00 
		$a_01_4 = {49 54 30 6c 56 6d 7a 33 } //01 00 
		$a_01_5 = {4e 79 4d 6f 31 35 4d } //00 00 
	condition:
		any of ($a_*)
 
}