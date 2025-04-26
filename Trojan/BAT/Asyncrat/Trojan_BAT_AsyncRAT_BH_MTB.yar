
rule Trojan_BAT_AsyncRAT_BH_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.BH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 11 07 72 ?? 00 00 70 28 ?? 00 00 06 28 ?? 00 00 2b 28 ?? 00 00 06 26 20 00 00 00 00 7e } //4
		$a_03_1 = {11 00 11 01 16 1a 28 ?? 00 00 06 26 20 } //2
	condition:
		((#a_03_0  & 1)*4+(#a_03_1  & 1)*2) >=6
 
}