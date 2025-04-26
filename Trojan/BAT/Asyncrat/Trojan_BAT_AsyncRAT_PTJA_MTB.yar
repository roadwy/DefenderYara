
rule Trojan_BAT_AsyncRAT_PTJA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.PTJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 16 08 28 9f 00 00 0a 28 9b 00 00 0a 11 04 16 11 04 8e 69 6f e0 00 00 0a 13 05 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}