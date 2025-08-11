
rule Trojan_BAT_PureLogStealer_AOYA_MTB{
	meta:
		description = "Trojan:BAT/PureLogStealer.AOYA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {1e 2d 4d 26 2b 4d 8e 69 8d ?? 00 00 01 2b 47 72 ?? ?? 00 70 1a 2d 42 26 16 2b 41 2b 1b 2b 40 09 06 09 91 08 09 08 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 09 17 58 0d 09 06 8e 69 32 df 07 0a de 23 73 ?? 00 00 0a 2b b0 28 ?? 00 00 0a 2b b0 0a 2b b1 06 2b b0 0b 2b b6 0c 2b bc 0d 2b bc 07 2b bd 26 de 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}