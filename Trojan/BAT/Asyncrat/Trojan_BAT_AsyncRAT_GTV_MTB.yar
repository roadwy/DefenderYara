
rule Trojan_BAT_AsyncRAT_GTV_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.GTV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 17 58 0c 08 1f 14 32 e1 20 88 13 00 00 28 } //5
		$a_03_1 = {0a 0c 06 08 16 08 8e 69 16 6f ?? 00 00 0a 26 20 c4 09 00 00 28 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}