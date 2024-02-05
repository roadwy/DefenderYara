
rule Trojan_BAT_Rozena_SPLE_MTB{
	meta:
		description = "Trojan:BAT/Rozena.SPLE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {00 09 11 0b 09 11 0b 91 18 59 20 90 01 03 00 5f d2 9c 00 11 0b 17 58 13 0b 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}