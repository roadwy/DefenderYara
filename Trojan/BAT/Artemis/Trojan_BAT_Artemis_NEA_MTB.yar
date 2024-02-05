
rule Trojan_BAT_Artemis_NEA_MTB{
	meta:
		description = "Trojan:BAT/Artemis.NEA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {08 09 07 09 07 8e 69 5d 91 02 09 91 61 d2 6f 90 01 01 00 00 0a 09 17 58 0d 09 02 8e 69 32 e3 90 00 } //05 00 
		$a_03_1 = {00 00 01 72 01 00 00 70 6f 90 01 01 00 00 0a 72 90 01 01 00 00 70 20 00 01 00 00 14 14 14 6f 90 01 01 00 00 0a 26 2a 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}