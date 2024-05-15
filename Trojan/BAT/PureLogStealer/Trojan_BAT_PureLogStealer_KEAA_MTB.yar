
rule Trojan_BAT_PureLogStealer_KEAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.KEAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {14 0a 02 16 3e 19 00 00 00 02 18 5d 3a 11 00 00 00 28 90 01 01 00 00 06 0a 28 90 01 01 00 00 0a 06 28 90 01 01 00 00 0a 28 90 01 01 00 00 0a 06 6f 90 00 } //01 00 
		$a_01_1 = {52 65 76 65 72 73 65 } //00 00  Reverse
	condition:
		any of ($a_*)
 
}