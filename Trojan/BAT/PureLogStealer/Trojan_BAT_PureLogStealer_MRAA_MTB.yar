
rule Trojan_BAT_PureLogStealer_MRAA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.MRAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_03_0 = {0a 0b 07 20 90 01 02 00 00 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 20 90 01 02 00 00 28 90 01 01 00 00 06 28 90 01 01 00 00 0a 6f 90 01 01 00 00 0a 0c 73 90 01 01 00 00 0a 0d 06 73 90 01 01 00 00 0a 13 04 11 04 08 16 73 90 01 01 00 00 0a 13 05 11 05 09 6f 90 01 01 00 00 0a 09 90 00 } //01 00 
		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00  FromBase64String
		$a_01_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //00 00  CreateDecryptor
	condition:
		any of ($a_*)
 
}