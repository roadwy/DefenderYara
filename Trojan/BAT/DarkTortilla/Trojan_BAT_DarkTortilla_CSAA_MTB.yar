
rule Trojan_BAT_DarkTortilla_CSAA_MTB{
	meta:
		description = "Trojan:BAT/DarkTortilla.CSAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {16 02 14 72 e8 14 00 70 16 8d 90 01 01 00 00 01 14 14 14 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 18 13 13 2b af 11 09 75 90 01 01 00 00 01 6f 90 01 01 00 00 0a 11 08 75 90 01 01 00 00 01 6f 90 01 01 00 00 0a 0d de 49 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}