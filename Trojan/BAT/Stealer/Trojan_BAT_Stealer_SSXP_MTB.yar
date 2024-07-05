
rule Trojan_BAT_Stealer_SSXP_MTB{
	meta:
		description = "Trojan:BAT/Stealer.SSXP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_03_0 = {16 30 06 73 90 01 03 0a 7a 03 28 90 01 03 0a 0a 02 7b 90 01 03 04 6f 90 01 03 0a 06 16 06 8e 69 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}