
rule Trojan_BAT_AsyncRAT_RDW_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.RDW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 01 00 00 2b 72 01 00 00 70 6f 04 00 00 0a 14 14 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}