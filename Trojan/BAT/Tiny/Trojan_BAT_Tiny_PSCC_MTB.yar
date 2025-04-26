
rule Trojan_BAT_Tiny_PSCC_MTB{
	meta:
		description = "Trojan:BAT/Tiny.PSCC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 0f 00 00 0a 25 72 01 00 00 70 6f 10 00 00 0a 25 72 75 00 00 70 6f 11 00 00 0a 25 16 6f 12 00 00 0a 28 13 00 00 0a 6f 14 00 00 0a 2a } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}