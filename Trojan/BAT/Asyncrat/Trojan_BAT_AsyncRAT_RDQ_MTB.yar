
rule Trojan_BAT_AsyncRAT_RDQ_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.RDQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 0b 00 00 0a 03 28 0c 00 00 0a 6f 0d 00 00 0a 0a 06 6f 0e 00 00 0a 14 14 6f 0f 00 00 0a 26 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}