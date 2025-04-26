
rule Backdoor_BAT_AgentTesla_SBR1_MSR{
	meta:
		description = "Backdoor:BAT/AgentTesla.SBR1!MSR,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 28 65 00 00 06 72 ?? 00 00 70 28 11 00 00 06 0a 28 2f 00 00 0a 06 6f 30 00 00 0a 0b 07 6f 31 00 00 0a 17 9a 0c 08 72 ?? 00 00 70 20 00 01 00 00 14 14 18 8d 04 00 00 01 25 16 7e 08 00 00 04 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}