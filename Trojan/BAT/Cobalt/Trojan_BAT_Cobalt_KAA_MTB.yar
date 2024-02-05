
rule Trojan_BAT_Cobalt_KAA_MTB{
	meta:
		description = "Trojan:BAT/Cobalt.KAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 05 00 "
		
	strings :
		$a_01_0 = {11 24 1d 11 09 5f 91 13 1c 11 1c 19 62 11 1c 1b 63 60 d2 13 1c 11 05 11 09 11 05 11 09 91 11 1c 61 d2 9c 11 09 17 58 13 09 11 09 11 07 32 d1 } //05 00 
		$a_01_1 = {11 28 11 0c 11 0d 11 0c 91 9d 17 11 0c 58 13 0c 11 0c 11 1a 32 ea } //00 00 
	condition:
		any of ($a_*)
 
}