
rule Trojan_BAT_Stealerc_AAUC_MTB{
	meta:
		description = "Trojan:BAT/Stealerc.AAUC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0a 0a 06 18 6f 90 01 01 00 00 0a 00 06 18 6f 90 01 01 00 00 0a 00 06 72 01 00 00 70 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 00 06 6f 90 01 01 00 00 0a 0b 07 28 90 01 01 00 00 06 16 28 90 01 01 00 00 06 8e 69 6f 90 01 01 00 00 0a 0c 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}