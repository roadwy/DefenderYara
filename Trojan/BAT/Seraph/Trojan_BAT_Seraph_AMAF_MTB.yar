
rule Trojan_BAT_Seraph_AMAF_MTB{
	meta:
		description = "Trojan:BAT/Seraph.AMAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 04 07 16 73 ?? 00 00 0a 13 05 11 05 09 6f ?? 00 00 0a 09 6f ?? 00 00 0a 28 ?? 00 00 06 de 2c } //1
		$a_03_1 = {0a 0b 14 0c 2b 0c 00 28 ?? 00 00 06 0c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}