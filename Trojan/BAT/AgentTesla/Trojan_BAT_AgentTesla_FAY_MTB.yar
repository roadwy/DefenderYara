
rule Trojan_BAT_AgentTesla_FAY_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FAY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0c 07 8e 69 17 da 13 18 16 13 19 2b 15 08 11 19 07 11 19 9a 1f 10 28 ?? 00 00 0a 9c 11 19 17 d6 13 19 11 19 11 18 31 e5 } //3
		$a_03_1 = {5a 00 69 00 6c 00 6c 00 69 00 6f 00 6e 00 54 00 65 00 63 00 68 00 6e 00 6f 00 6c 00 6f 00 67 00 69 00 65 00 73 00 53 00 61 00 6c 00 65 00 73 00 [0-05] 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //2
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*2) >=5
 
}