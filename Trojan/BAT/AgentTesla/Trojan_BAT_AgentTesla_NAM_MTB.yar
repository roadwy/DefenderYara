
rule Trojan_BAT_AgentTesla_NAM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 6f 82 00 00 06 2d 10 02 16 1c 2d 04 26 26 2b 07 28 ?? 00 00 06 2b 00 02 06 28 ?? 00 00 06 } //5
		$a_01_1 = {45 74 73 74 67 64 74 74 62 6e 63 71 61 6a } //1 Etstgdttbncqaj
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}