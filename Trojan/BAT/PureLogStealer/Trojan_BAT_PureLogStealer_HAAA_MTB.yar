
rule Trojan_BAT_PureLogStealer_HAAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.HAAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {0a 11 06 18 6f 90 01 01 00 00 0a 11 06 11 05 08 6f 90 01 01 00 00 0a 13 07 09 73 90 01 01 00 00 0a 13 08 11 08 11 07 16 73 90 01 01 00 00 0a 13 09 11 09 28 90 01 01 00 00 0a 73 90 01 01 00 00 0a 13 0a 11 0a 6f 90 01 01 00 00 0a 13 0b dd 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}