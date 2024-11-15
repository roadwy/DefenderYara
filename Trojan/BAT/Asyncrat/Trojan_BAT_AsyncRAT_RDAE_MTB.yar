
rule Trojan_BAT_AsyncRAT_RDAE_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.RDAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 11 0c 95 13 0f 11 0e 11 0f 61 13 10 09 11 0d 11 10 d2 9c 11 05 17 58 13 05 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}