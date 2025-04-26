
rule Trojan_BAT_NewBotLoader_CCHU_MTB{
	meta:
		description = "Trojan:BAT/NewBotLoader.CCHU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {20 45 00 00 00 28 ?? 00 00 0a a2 25 20 01 00 00 00 20 72 00 00 00 28 ?? 00 00 0a a2 25 20 02 00 00 00 20 72 00 00 00 28 ?? 00 00 0a a2 25 20 03 00 00 00 20 6f 00 00 00 28 ?? 00 00 0a a2 25 20 04 00 00 00 20 72 00 00 00 28 ?? 00 00 0a a2 28 ?? 00 00 0a fe 09 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}