
rule Trojan_BAT_RedlineStealer_SXA_MTB{
	meta:
		description = "Trojan:BAT/RedlineStealer.SXA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,28 00 28 00 02 00 00 "
		
	strings :
		$a_03_0 = {2d 0f 06 28 ?? 00 00 0a 2d 07 06 28 ?? 00 00 0a 26 03 28 ?? 00 00 0a 0b 04 07 28 ?? 00 00 0a 73 ?? 00 00 0a 0c 08 04 } //30
		$a_03_1 = {02 03 06 04 06 59 6f ?? 00 00 0a 0b 07 2d 02 06 2a 06 07 58 0a 06 04 32 e7 } //10
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*10) >=40
 
}