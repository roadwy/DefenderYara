
rule Trojan_BAT_AgentTesla_ASBO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASBO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 04 09 8e 69 17 da 13 1d 16 13 1e 2b 1a 11 04 09 11 1e 9a 1f 10 28 ?? 01 00 0a b4 6f ?? 01 00 0a 00 11 1e 17 d6 13 1e 11 1e 11 1d 31 e0 } //4
		$a_01_1 = {43 00 6f 00 6f 00 6c 00 65 00 72 00 4d 00 61 00 73 00 74 00 65 00 72 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 CoolerMaster.Resources
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}