
rule Trojan_BAT_RedlineStealer_RPX_MTB{
	meta:
		description = "Trojan:BAT/RedlineStealer.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 08 17 58 20 00 01 00 00 5d 0c 09 06 08 91 58 20 00 01 00 00 5d 0d 06 08 91 13 07 06 08 06 09 91 9c } //00 00 
	condition:
		any of ($a_*)
 
}