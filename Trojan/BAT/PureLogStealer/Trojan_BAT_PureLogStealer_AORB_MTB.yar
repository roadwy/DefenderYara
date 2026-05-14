
rule Trojan_BAT_PureLogStealer_AORB_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.AORB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 09 14 fe 03 13 06 11 06 2c 05 17 13 0b 2b cb 16 2b f9 09 07 28 ?? ?? 00 06 00 09 6f ?? ?? 00 0a 13 07 11 07 02 16 02 8e 69 6f ?? ?? 00 0a 0a de 46 00 de 1b } //5
		$a_01_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //1 CreateDecryptor
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}