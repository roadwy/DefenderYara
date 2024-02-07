
rule Trojan_BAT_Nanocore_AEOCG_MTB{
	meta:
		description = "Trojan:BAT/Nanocore.AEOCG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 02 00 "
		
	strings :
		$a_01_0 = {13 0b 11 04 11 06 11 0a 58 11 09 11 0a 91 11 0b 61 d2 9c 11 0a 17 58 13 0a 11 0a 11 09 8e 69 32 d8 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //00 00  FromBase64String
	condition:
		any of ($a_*)
 
}