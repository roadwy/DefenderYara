
rule Trojan_BAT_Bobik_PTAZ_MTB{
	meta:
		description = "Trojan:BAT/Bobik.PTAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {6f 1f 00 00 0a 03 28 90 01 01 00 00 0a 13 05 11 05 2c 10 00 02 11 04 09 28 90 01 01 00 00 06 00 17 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}