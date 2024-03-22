
rule Trojan_BAT_PureLogStealer_EFAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.EFAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {06 07 06 8e 69 5d 91 11 0b 61 13 0c 06 11 09 06 8e 69 5d 91 13 0d 11 0c 11 0d 20 00 01 00 00 58 59 13 0e 06 07 06 } //00 00 
	condition:
		any of ($a_*)
 
}