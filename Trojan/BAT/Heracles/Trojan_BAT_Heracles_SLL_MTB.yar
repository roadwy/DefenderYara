
rule Trojan_BAT_Heracles_SLL_MTB{
	meta:
		description = "Trojan:BAT/Heracles.SLL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 00 28 07 00 00 0a 25 14 28 08 00 00 0a 39 06 00 00 00 73 06 00 00 0a 7a 72 01 00 00 70 6f 09 00 00 0a } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}