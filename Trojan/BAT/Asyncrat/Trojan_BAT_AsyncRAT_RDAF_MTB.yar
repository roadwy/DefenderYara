
rule Trojan_BAT_AsyncRAT_RDAF_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.RDAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {d0 27 00 00 01 28 29 00 00 0a 11 0a 11 07 17 6f 2a 00 00 0a 28 2b 00 00 0a 28 01 00 00 2b 6f 2d 00 00 0a 26 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}