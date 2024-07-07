
rule Trojan_BAT_AgentTesla_SOL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SOL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {11 0d 11 10 61 13 11 11 07 11 0c d4 11 11 20 ff 00 00 00 5f d2 9c 1f 37 13 15 38 68 f9 } //1
		$a_81_1 = {56 37 47 55 47 34 35 48 30 43 37 35 5a 35 41 45 37 34 38 37 55 51 } //1 V7GUG45H0C75Z5AE7487UQ
		$a_81_2 = {4a 6f 6b 65 6e 70 6f 2e 50 72 6f 70 65 72 74 69 65 73 } //1 Jokenpo.Properties
	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}