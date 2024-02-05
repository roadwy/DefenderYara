
rule Trojan_BAT_Rozena_CXJQ_MTB{
	meta:
		description = "Trojan:BAT/Rozena.CXJQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 16 06 8e 69 20 90 01 04 1f 40 28 90 01 04 0d 06 16 09 6e 28 90 01 04 06 8e 69 28 90 01 04 00 7e 90 01 04 13 04 16 16 09 11 04 16 12 02 28 90 01 04 0b 07 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}