
rule Trojan_BAT_AgentTesla_MBJB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBJB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4a 00 56 00 4e 00 4a 00 2a 00 41 00 44 00 2a 00 2a 00 41 00 42 00 2a 00 2a 00 41 00 50 00 37 00 37 00 59 00 2a 00 43 00 34 00 2a 00 2a 00 2a 00 2a 00 2a 00 41 00 43 00 2a 00 2a 00 2a } //1
		$a_01_1 = {55 00 58 00 41 00 32 00 44 00 49 00 4b 00 45 00 51 00 2a 00 2a 00 2a 00 2a 00 2a 00 41 00 55 00 43 00 46 00 2a 00 41 00 45 00 59 00 41 00 49 00 44 00 41 00 44 00 47 00 46 00 53 00 47 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}