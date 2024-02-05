
rule Trojan_BAT_Rozena_AN_MTB{
	meta:
		description = "Trojan:BAT/Rozena.AN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {0b 16 13 04 2b 18 07 11 04 07 11 04 91 1f 11 59 20 ff 00 00 00 5f d2 9c 11 04 17 58 13 04 11 04 07 8e 69 32 e1 } //00 00 
	condition:
		any of ($a_*)
 
}