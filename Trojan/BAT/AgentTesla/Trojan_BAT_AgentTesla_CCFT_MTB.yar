
rule Trojan_BAT_AgentTesla_CCFT_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CCFT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {34 00 44 00 35 00 41 00 39 00 5b 00 5d 00 5b 00 5d 00 33 00 5b 00 5d 00 5b 00 5d 00 5b 00 5d 00 30 00 34 00 5b 00 5d 00 5b 00 5d 00 5b 00 5d 00 46 00 46 00 46 00 46 00 5b 00 5d 00 5b 00 5d 00 42 00 38 } //1
		$a_01_1 = {46 00 30 00 36 00 37 00 35 00 30 00 34 00 5b 00 5d 00 5b 00 5d 00 31 00 42 00 36 00 46 00 30 00 35 00 5b 00 5d 00 5b 00 5d 00 30 00 41 00 30 00 41 00 31 00 31 00 30 00 39 00 32 00 30 00 43 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}