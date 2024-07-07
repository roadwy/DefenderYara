
rule Trojan_BAT_AgentTesla_MBZC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d } //1
		$a_81_1 = {47 54 48 56 48 48 35 47 47 59 46 43 44 46 47 38 55 44 38 35 56 49 } //1 GTHVHH5GGYFCDFG8UD85VI
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}