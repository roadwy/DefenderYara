
rule Trojan_BAT_Disfa_AAJT_MTB{
	meta:
		description = "Trojan:BAT/Disfa.AAJT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {13 04 16 07 8e b7 17 da 13 07 13 05 2b 19 11 04 07 11 05 9a 6f 90 01 01 00 00 0a 28 90 01 01 00 00 0a 13 04 00 11 05 17 d6 13 05 11 05 11 07 13 09 11 09 31 dd 90 00 } //01 00 
		$a_01_1 = {53 74 72 52 65 76 65 72 73 65 } //01 00  StrReverse
		$a_01_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}