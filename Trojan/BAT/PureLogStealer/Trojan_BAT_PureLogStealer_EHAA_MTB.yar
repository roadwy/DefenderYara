
rule Trojan_BAT_PureLogStealer_EHAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.EHAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 04 00 "
		
	strings :
		$a_03_0 = {0b 07 8e 69 20 00 04 00 00 2e f0 08 15 3e 90 01 01 00 00 00 07 28 90 01 01 00 00 2b 28 90 01 01 00 00 2b 0b 90 00 } //01 00 
		$a_01_1 = {52 65 76 65 72 73 65 } //00 00  Reverse
	condition:
		any of ($a_*)
 
}