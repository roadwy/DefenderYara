
rule Trojan_BAT_Seraph_PSKQ_MTB{
	meta:
		description = "Trojan:BAT/Seraph.PSKQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {72 63 00 00 70 28 08 00 00 06 0b 28 1a 00 00 0a 07 6f 1b 00 00 0a 72 ab 00 00 70 7e 1c 00 00 0a 6f 1d 00 00 0a 28 1e 00 00 0a 0c de 17 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}