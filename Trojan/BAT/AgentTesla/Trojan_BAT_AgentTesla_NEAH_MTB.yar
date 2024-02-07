
rule Trojan_BAT_AgentTesla_NEAH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {61 66 52 79 56 51 44 47 78 74 41 } //05 00  afRyVQDGxtA
		$a_01_1 = {4d 53 52 47 63 79 4d 70 6a } //05 00  MSRGcyMpj
		$a_01_2 = {44 4b 76 7a 4b 70 } //02 00  DKvzKp
		$a_01_3 = {43 6f 6e 66 75 73 65 72 2e 43 6f 72 65 20 31 2e 36 2e 30 2b 34 34 37 33 34 31 39 36 34 66 } //01 00  Confuser.Core 1.6.0+447341964f
		$a_01_4 = {49 6e 76 6f 6b 65 4d 65 6d 62 65 72 } //00 00  InvokeMember
	condition:
		any of ($a_*)
 
}