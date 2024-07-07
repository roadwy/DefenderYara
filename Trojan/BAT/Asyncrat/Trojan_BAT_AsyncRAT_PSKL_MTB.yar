
rule Trojan_BAT_AsyncRAT_PSKL_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.PSKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8d 03 00 00 01 0a 73 02 00 00 0a 28 90 01 03 0a 03 6f 90 01 03 0a 28 90 01 03 0a 25 16 06 16 1f 10 28 90 01 03 0a 16 06 1f 0f 1f 10 28 90 01 03 0a 25 06 6f 90 01 03 0a 25 18 6f 90 01 03 0a 6f 90 01 03 0a 02 16 02 8e 69 6f 0a 00 00 0a 2a 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}