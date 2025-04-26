
rule Trojan_BAT_AsyncRAT_RDAD_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.RDAD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 17 11 17 11 15 28 1e 00 00 0a 6f 1f 00 00 0a 6f 1f 00 00 0a 13 16 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}