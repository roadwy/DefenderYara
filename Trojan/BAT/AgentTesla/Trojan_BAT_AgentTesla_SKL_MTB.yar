
rule Trojan_BAT_AgentTesla_SKL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {04 08 03 08 91 05 09 95 61 d2 9c 00 08 17 58 0c 08 03 8e 69 fe 04 13 06 11 06 2d 80 } //1
		$a_81_1 = {4e 42 43 56 35 34 37 38 35 37 50 30 54 35 54 34 42 37 35 43 34 4a } //1 NBCV547857P0T5T4B75C4J
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}