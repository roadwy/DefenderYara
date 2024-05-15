
rule Trojan_BAT_NjRAT_PTJP_MTB{
	meta:
		description = "Trojan:BAT/NjRAT.PTJP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {8d 1a 00 00 01 13 0a 08 11 0a 16 1a 28 90 01 01 00 00 06 26 11 0a 16 28 90 01 01 00 00 06 13 06 73 26 00 00 06 13 08 1b 8d 1a 00 00 01 13 09 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}