
rule Trojan_BAT_Heracles_MAAK_MTB{
	meta:
		description = "Trojan:BAT/Heracles.MAAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 00 79 00 6e 00 25 00 25 00 61 00 6d 00 25 00 25 00 69 00 63 00 49 00 6e 00 76 00 25 00 25 00 6f 00 6b 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}