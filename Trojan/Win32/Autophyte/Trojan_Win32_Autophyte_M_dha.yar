
rule Trojan_Win32_Autophyte_M_dha{
	meta:
		description = "Trojan:Win32/Autophyte.M!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {3b 2a 2a 3b 00 } //01 00 
		$a_01_1 = {3a 47 59 3a 00 } //01 00 
		$a_01_2 = {3a 46 5a 3a 00 } //01 00 
		$a_01_3 = {4d 44 2a 2e 74 6d 70 00 } //01 00 
		$a_01_4 = {44 57 53 2a 2e 74 6d 70 00 } //01 00 
		$a_01_5 = {50 4d 2a 2e 74 6d 70 00 } //01 00 
		$a_01_6 = {46 4d 2a 2e 74 6d 70 00 } //01 00 
		$a_01_7 = {57 4d 2a 2e 74 6d 70 00 } //01 00 
		$a_01_8 = {44 57 53 30 30 00 } //00 00 
	condition:
		any of ($a_*)
 
}