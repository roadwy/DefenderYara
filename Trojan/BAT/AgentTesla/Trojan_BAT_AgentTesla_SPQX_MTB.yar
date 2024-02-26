
rule Trojan_BAT_AgentTesla_SPQX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SPQX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_81_0 = {45 50 30 42 52 44 73 72 6b 74 70 42 52 33 33 36 } //01 00  EP0BRDsrktpBR336
		$a_81_1 = {6d 73 65 6e 63 68 69 6a 4b 43 61 74 74 } //01 00  msenchijKCatt
		$a_81_2 = {77 30 30 64 67 54 53 6f 63 6b 65 6e 65 44 70 73 } //01 00  w00dgTSockeneDps
		$a_81_3 = {6f 6d 71 74 7a 73 6f 66 74 37 57 32 38 35 2e 64 6c 6c } //00 00  omqtzsoft7W285.dll
	condition:
		any of ($a_*)
 
}