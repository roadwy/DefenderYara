
rule Trojan_BAT_Mardom_BNAA_MTB{
	meta:
		description = "Trojan:BAT/Mardom.BNAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {04 03 04 58 11 01 58 } //4
		$a_01_1 = {52 65 76 65 72 73 65 } //1 Reverse
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}