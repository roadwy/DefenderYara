
rule Trojan_BAT_PureLogStealer_KAAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.KAAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_03_0 = {2b 19 2b 1a 2b 1f 2b 20 2b 21 7d 90 01 01 00 00 04 de 24 28 90 01 01 00 00 06 2b e4 0a 2b e5 06 2b e4 28 90 01 01 00 00 0a 2b df 02 2b de 06 2b dd 28 90 01 01 00 00 0a 2b d8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}