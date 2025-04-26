
rule Trojan_BAT_PureLogStealer_AMAK_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.AMAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 25 17 6f ?? 00 00 0a 25 18 6f ?? 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 2b 28 ?? 00 00 06 28 ?? 00 00 2b 6f ?? 00 00 0a 0a 06 02 16 02 8e 69 6f ?? 00 00 0a 0b de 0a } //3
		$a_03_1 = {0a 14 1a 8d ?? 00 00 01 25 16 02 a2 25 17 03 a2 25 18 06 8c ?? 00 00 01 a2 25 19 04 a2 } //1
		$a_80_2 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 } //CreateDecryptor  1
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*1+(#a_80_2  & 1)*1) >=5
 
}