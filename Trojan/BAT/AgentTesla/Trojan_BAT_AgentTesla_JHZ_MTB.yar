
rule Trojan_BAT_AgentTesla_JHZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JHZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {08 11 06 07 94 58 11 05 07 94 58 20 00 01 00 00 5d 0c 11 06 07 94 13 04 11 06 07 11 06 08 94 9e 11 06 08 11 04 9e 07 17 58 0b } //1
		$a_81_1 = {55 73 71 71 6c 72 6a 75 70 6a 79 79 62 75 75 73 } //1 Usqqlrjupjyybuus
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}