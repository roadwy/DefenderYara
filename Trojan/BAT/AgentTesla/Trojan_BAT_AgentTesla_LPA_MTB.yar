
rule Trojan_BAT_AgentTesla_LPA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.LPA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 09 11 04 11 05 28 ?? ?? ?? 06 13 06 08 07 02 11 06 28 ?? ?? ?? 06 d2 9c 00 11 05 17 58 13 05 11 05 17 fe 04 13 07 11 07 2d d4 } //1
		$a_81_1 = {54 30 6f 30 57 69 30 6e 30 33 30 32 } //1 T0o0Wi0n0302
	condition:
		((#a_03_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}