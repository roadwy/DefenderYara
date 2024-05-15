
rule Trojan_BAT_PureLogStealer_LTAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.LTAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {06 20 b2 b7 b5 c0 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 20 91 b7 b5 c0 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 13 05 73 90 01 01 00 00 0a 0b 11 04 73 90 01 01 00 00 0a 0c 08 11 05 16 73 90 01 01 00 00 0a 0d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}