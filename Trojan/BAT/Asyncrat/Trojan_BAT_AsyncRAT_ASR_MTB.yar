
rule Trojan_BAT_AsyncRAT_ASR_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.ASR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 a2 25 17 7e 90 01 03 0a a2 25 18 09 a2 25 19 17 8c 90 01 03 01 a2 13 04 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}