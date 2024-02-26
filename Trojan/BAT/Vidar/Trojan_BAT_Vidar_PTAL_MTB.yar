
rule Trojan_BAT_Vidar_PTAL_MTB{
	meta:
		description = "Trojan:BAT/Vidar.PTAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {0a 38 a5 ff ff ff 11 02 28 90 01 01 00 00 0a 04 6f 98 00 00 0a 6f 99 00 00 0a 13 01 38 71 ff ff ff 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}