
rule Trojan_BAT_Quasar_MBCO_MTB{
	meta:
		description = "Trojan:BAT/Quasar.MBCO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 72 05 02 00 70 72 01 00 00 70 6f 90 01 01 00 00 0a 10 00 02 6f 90 01 01 00 00 0a 18 5b 8d 90 01 01 00 00 01 0a 16 0b 38 18 00 00 00 06 07 02 07 18 5a 18 6f 90 01 01 00 00 0a 1f 10 28 90 01 01 00 00 0a 9c 07 17 58 0b 07 06 8e 69 32 e2 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}