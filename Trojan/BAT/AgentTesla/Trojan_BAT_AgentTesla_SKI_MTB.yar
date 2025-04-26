
rule Trojan_BAT_AgentTesla_SKI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SKI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {25 16 12 00 28 ?? 00 00 0a 9c 25 17 12 00 28 ?? 00 00 0a 9c 25 18 12 00 28 ?? 00 00 0a 9c 07 28 } //1
		$a_81_1 = {42 6c 6f 6f 64 42 61 6e 6b 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } //1 BloodBank.Properties.Resources.resources
		$a_81_2 = {42 6c 6f 6f 64 42 61 6e 6b 2e 52 65 63 6f 72 64 73 2e 72 65 73 6f 75 72 63 65 73 } //1 BloodBank.Records.resources
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}