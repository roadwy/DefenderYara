
rule Trojan_BAT_AsyncRAT_BB_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.BB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 00 0a 13 08 07 11 08 6f 90 09 13 00 11 07 28 ?? 00 00 0a 72 ?? 01 00 70 6f ?? 00 00 0a 6f } //2
		$a_01_1 = {0a 0c 08 06 16 06 8e 69 6f } //2
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}