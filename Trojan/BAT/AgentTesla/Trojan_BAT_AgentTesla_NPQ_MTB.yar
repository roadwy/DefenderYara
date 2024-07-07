
rule Trojan_BAT_AgentTesla_NPQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NPQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 11 04 20 00 14 01 00 5d 07 11 04 20 00 14 01 00 5d 91 08 11 04 1f 16 5d 28 f2 00 00 06 61 07 11 04 17 58 20 00 14 01 00 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d } //1
		$a_80_1 = {48 54 48 34 34 34 46 43 35 46 56 38 57 41 35 41 37 38 38 38 37 45 } //HTH444FC5FV8WA5A78887E  1
	condition:
		((#a_01_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}