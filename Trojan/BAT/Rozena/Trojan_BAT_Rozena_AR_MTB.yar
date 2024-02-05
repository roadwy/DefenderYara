
rule Trojan_BAT_Rozena_AR_MTB{
	meta:
		description = "Trojan:BAT/Rozena.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0a 06 20 ff 01 0f 00 28 90 01 03 06 72 39 00 00 70 0b 25 15 19 16 07 14 14 14 14 14 14 28 90 01 03 06 26 16 14 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}