
rule Backdoor_BAT_AgentTesla_F_MTB{
	meta:
		description = "Backdoor:BAT/AgentTesla.F!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 06 02 06 91 90 02 0b 8e 69 5d 91 61 d2 9c 90 00 } //1
		$a_01_1 = {24 65 32 61 33 36 31 61 36 2d 37 38 61 30 2d 34 30 64 31 2d 38 39 63 30 2d 38 39 33 32 37 64 38 39 61 64 66 38 } //1 $e2a361a6-78a0-40d1-89c0-89327d89adf8
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}