
rule Trojan_BAT_AsyncRAT_BGC_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.BGC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 09 17 59 06 09 91 07 61 1f 0d 59 20 ff 00 00 00 5f d2 9c 09 17 58 0d 09 06 8e 69 32 e2 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}