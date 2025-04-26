
rule Trojan_BAT_AsyncRAT_RDAC_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.RDAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 08 17 73 1f 00 00 0a 13 04 11 04 06 16 06 8e 69 6f 20 00 00 0a 09 6f 21 00 00 0a 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}