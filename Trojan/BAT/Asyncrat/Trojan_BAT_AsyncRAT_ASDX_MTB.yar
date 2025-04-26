
rule Trojan_BAT_AsyncRAT_ASDX_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.ASDX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {61 11 0a 11 0d 91 61 b4 9c 11 0d 03 6f ?? 00 00 0a 17 da 33 05 16 13 0d 2b 06 11 0d 17 d6 13 0d 11 0f 17 d6 13 0f 11 0f 11 10 31 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}