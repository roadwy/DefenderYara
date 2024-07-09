
rule Trojan_BAT_AgentTesla_ABUN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABUN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {16 0d 2b 1d 07 09 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 13 05 08 11 05 6f ?? 00 00 0a 09 18 58 0d 09 07 6f ?? 00 00 0a 32 da } //4
		$a_01_1 = {4f 00 70 00 74 00 69 00 6b 00 73 00 5f 00 43 00 53 00 68 00 61 00 72 00 70 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 } //1 Optiks_CSharp.Properties.Resources
	condition:
		((#a_03_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}