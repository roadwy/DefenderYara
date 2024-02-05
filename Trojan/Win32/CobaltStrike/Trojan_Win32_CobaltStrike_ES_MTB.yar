
rule Trojan_Win32_CobaltStrike_ES_MTB{
	meta:
		description = "Trojan:Win32/CobaltStrike.ES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 52 70 37 30 } //01 00 
		$a_01_1 = {7a 6b 50 78 33 30 30 39 } //01 00 
		$a_01_2 = {6d 67 75 72 37 33 30 79 77 31 2e 64 6c 6c } //01 00 
		$a_01_3 = {64 72 69 76 65 } //00 00 
	condition:
		any of ($a_*)
 
}