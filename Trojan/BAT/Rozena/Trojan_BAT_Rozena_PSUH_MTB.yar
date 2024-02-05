
rule Trojan_BAT_Rozena_PSUH_MTB{
	meta:
		description = "Trojan:BAT/Rozena.PSUH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {72 01 00 00 70 28 90 01 01 00 00 0a 0a 7e 14 00 00 0a 06 8e 69 20 00 10 00 00 1f 40 28 90 01 01 00 00 06 0b 06 16 07 06 8e 69 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}