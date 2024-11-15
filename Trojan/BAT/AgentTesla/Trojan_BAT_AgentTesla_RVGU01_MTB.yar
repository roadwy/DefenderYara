
rule Trojan_BAT_AgentTesla_RVGU01_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RVGU01!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {37 38 32 32 30 38 33 65 2d 38 61 30 34 2d 34 62 37 37 2d 38 65 32 33 2d 63 66 36 34 37 38 65 61 32 34 30 39 } //1 7822083e-8a04-4b77-8e23-cf6478ea2409
		$a_81_1 = {4d 65 6e 75 54 72 79 } //1 MenuTry
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}