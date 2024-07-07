
rule Trojan_BAT_AsyncRAT_PSTF_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.PSTF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {25 80 12 00 00 04 28 10 00 00 0a 26 73 11 00 00 0a 20 e8 03 00 00 20 88 13 00 00 6f 12 00 00 0a 28 0c 00 00 0a 73 f7 01 00 06 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}