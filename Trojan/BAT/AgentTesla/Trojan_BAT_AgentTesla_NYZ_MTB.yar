
rule Trojan_BAT_AgentTesla_NYZ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NYZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {24 65 63 38 65 30 63 32 39 2d 34 39 36 63 2d 34 66 38 61 2d 62 34 66 65 2d 61 39 35 36 66 30 36 63 32 35 34 66 } //1 $ec8e0c29-496c-4f8a-b4fe-a956f06c254f
		$a_01_1 = {57 95 a2 2b 09 1f 00 00 00 fa 25 33 00 16 00 00 01 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}