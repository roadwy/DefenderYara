
rule Trojan_BAT_PureLogStealer_DTAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.DTAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {08 09 58 0c 09 17 58 0d 09 02 31 f4 } //02 00 
		$a_01_1 = {11 04 11 05 5a 13 04 11 05 17 58 13 05 11 05 02 31 ee } //01 00 
		$a_01_2 = {52 65 76 65 72 73 65 } //00 00  Reverse
	condition:
		any of ($a_*)
 
}