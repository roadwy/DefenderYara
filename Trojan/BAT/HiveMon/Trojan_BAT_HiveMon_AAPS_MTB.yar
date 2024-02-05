
rule Trojan_BAT_HiveMon_AAPS_MTB{
	meta:
		description = "Trojan:BAT/HiveMon.AAPS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 0b 72 01 00 00 70 6f 90 01 01 00 00 0a 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 13 0c 11 0b 72 49 00 00 70 72 91 00 00 70 72 a1 00 00 70 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 13 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}