
rule Trojan_BAT_PureLogStealer_KDAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.KDAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {11 08 72 6d 00 00 70 28 90 01 01 00 00 0a 72 9f 00 00 70 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 13 09 73 90 01 01 00 00 0a 13 0a 11 07 73 90 01 01 00 00 0a 13 0b 11 0b 11 09 16 73 90 01 01 00 00 0a 13 0c 11 0c 11 0a 6f 90 01 01 00 00 0a 11 0a 6f 90 01 01 00 00 0a 13 07 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}