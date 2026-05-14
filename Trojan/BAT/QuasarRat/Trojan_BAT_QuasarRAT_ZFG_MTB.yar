
rule Trojan_BAT_QuasarRAT_ZFG_MTB{
	meta:
		description = "Trojan:BAT/QuasarRAT.ZFG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 11 12 11 13 6f ?? 00 00 0a 13 14 11 0b 03 fe 04 13 15 11 15 2c 17 00 11 08 12 14 28 ?? 00 00 0a 6f ?? 00 00 0a 00 11 0b 17 58 13 0b } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}