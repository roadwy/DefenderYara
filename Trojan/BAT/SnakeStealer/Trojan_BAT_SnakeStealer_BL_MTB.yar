
rule Trojan_BAT_SnakeStealer_BL_MTB{
	meta:
		description = "Trojan:BAT/SnakeStealer.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 0a 16 0b 2b 0d 04 06 07 91 6f ?? 00 00 0a 07 17 58 0b 07 03 32 } //4
		$a_03_1 = {02 03 04 6f ?? 00 00 0a 0e 04 05 6f ?? 00 00 0a 59 0a 06 05 28 } //1
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*1) >=5
 
}