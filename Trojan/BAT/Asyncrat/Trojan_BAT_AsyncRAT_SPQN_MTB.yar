
rule Trojan_BAT_AsyncRAT_SPQN_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.SPQN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 06 03 06 91 1f 7b 61 d2 9c 06 17 58 0a 06 03 8e 69 32 ec } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}