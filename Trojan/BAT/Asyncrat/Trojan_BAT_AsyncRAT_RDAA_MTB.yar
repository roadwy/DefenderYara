
rule Trojan_BAT_AsyncRAT_RDAA_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.RDAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 06 8f 24 00 00 01 25 71 24 00 00 01 1f 32 59 d2 81 24 00 00 01 00 06 17 58 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}