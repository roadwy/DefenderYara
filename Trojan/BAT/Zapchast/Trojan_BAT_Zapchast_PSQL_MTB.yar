
rule Trojan_BAT_Zapchast_PSQL_MTB{
	meta:
		description = "Trojan:BAT/Zapchast.PSQL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {2f 1f 73 0a 00 00 0a 0a 06 72 0f 00 00 70 6f 90 01 03 0a 06 17 6f 90 01 03 0a 06 28 90 01 03 0a 26 de 0e 0b 07 28 90 01 03 0a 28 0f 00 00 0a de 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}