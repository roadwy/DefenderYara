
rule Trojan_BAT_AgentTesla_ASBN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASBN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 09 8e 69 17 da 13 1d 16 13 1e 2b 1c 11 04 11 1e 09 11 1e 9a 1f 10 28 ?? 00 00 0a b4 6f ?? 00 00 0a 00 11 1e 17 d6 13 1e 11 1e 11 1d 31 de } //4
		$a_01_1 = {46 00 69 00 6e 00 61 00 6c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 5f 00 54 00 75 00 72 00 6e 00 65 00 72 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 FinalProject_Turner.Resources
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}