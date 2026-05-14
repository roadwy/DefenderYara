
rule Trojan_BAT_XWorm_ZMJ_MTB{
	meta:
		description = "Trojan:BAT/XWorm.ZMJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {25 16 03 6f ?? 01 00 0a 0a 12 00 28 ?? 01 00 0a 9c 25 17 03 6f ?? 01 00 0a 0a 12 00 28 ?? 01 00 0a 9c 25 18 03 6f ?? 01 00 0a 0a 12 00 28 ?? 01 00 0a 9c 2a } //6
		$a_03_1 = {04 03 02 7b ?? 00 00 04 7b ?? 00 00 04 02 7b ?? 00 00 04 03 6f ?? 01 00 0a 73 ?? 01 00 0a 2a } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}