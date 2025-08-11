
rule Trojan_BAT_Remcos_ZPT_MTB{
	meta:
		description = "Trojan:BAT/Remcos.ZPT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 59 13 18 73 ?? 00 00 0a 13 19 11 19 72 94 22 00 70 12 16 28 ?? 01 00 0a 12 16 28 ?? 01 00 0a 58 12 16 28 ?? 01 00 0a 58 6c 23 00 00 00 00 00 00 08 40 5b 23 00 00 00 00 00 e0 6f 40 5b } //6
		$a_03_1 = {02 12 06 28 ?? 01 00 0a 12 06 28 ?? 01 00 0a 6f ?? 01 00 0a 13 16 12 06 28 ?? 01 00 0a 13 1b 12 1b 28 ?? 00 00 0a 12 06 } //5
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*5) >=11
 
}