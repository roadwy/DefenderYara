
rule Trojan_BAT_AgentTesla_MBKK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4a 00 56 00 4e 00 4a 00 23 00 41 00 44 00 23 00 23 00 41 00 60 00 23 00 23 00 41 00 50 00 37 00 37 00 59 00 23 00 43 00 34 00 23 00 23 00 23 00 23 00 23 00 41 00 43 00 23 00 23 00 23 00 23 00 23 00 23 00 23 00 23 00 23 00 23 00 23 00 23 00 23 } //1
		$a_01_1 = {38 2d 66 36 65 64 32 63 30 65 33 30 66 36 } //1 8-f6ed2c0e30f6
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}