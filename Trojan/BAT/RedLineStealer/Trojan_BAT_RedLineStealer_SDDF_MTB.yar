
rule Trojan_BAT_RedLineStealer_SDDF_MTB{
	meta:
		description = "Trojan:BAT/RedLineStealer.SDDF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 04 00 "
		
	strings :
		$a_01_0 = {5d 0b 08 11 04 07 91 58 20 00 01 00 00 5d 0c 16 13 10 } //00 00 
	condition:
		any of ($a_*)
 
}