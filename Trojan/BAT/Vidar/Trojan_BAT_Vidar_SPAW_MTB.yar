
rule Trojan_BAT_Vidar_SPAW_MTB{
	meta:
		description = "Trojan:BAT/Vidar.SPAW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0a 13 04 02 0d 11 04 09 16 09 8e b7 6f 37 00 00 0a 0b 90 0a 1e 00 06 18 6f 90 01 03 0a 06 6f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}