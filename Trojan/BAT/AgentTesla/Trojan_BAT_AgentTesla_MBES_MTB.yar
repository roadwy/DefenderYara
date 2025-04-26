
rule Trojan_BAT_AgentTesla_MBES_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 08 09 28 ?? 00 00 06 09 [0-10] 6f ?? 00 00 0a 09 13 04 de 1c } //1
		$a_01_1 = {24 61 35 65 39 30 61 66 35 2d 65 30 30 61 2d 34 62 34 37 2d 39 63 36 65 2d 62 39 63 65 32 61 63 36 34 61 66 36 } //1 $a5e90af5-e00a-4b47-9c6e-b9ce2ac64af6
		$a_01_2 = {46 75 63 6b 2e 50 72 6f 70 65 72 74 69 65 73 } //1 Fuck.Properties
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_BAT_AgentTesla_MBES_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {34 00 44 00 2d 00 35 00 41 00 2d 00 39 00 23 00 2d 00 23 00 23 00 2d 00 23 00 33 00 2d 00 23 00 23 00 2d 00 23 00 23 00 2d 00 23 00 23 00 2d 00 23 00 34 00 2d 00 23 00 23 00 2d 00 23 00 23 00 2d 00 23 00 23 00 2d 00 46 00 46 00 2d 00 46 00 46 00 } //1 4D-5A-9#-##-#3-##-##-##-#4-##-##-##-FF-FF
		$a_01_1 = {46 00 2d 00 36 00 34 00 2d 00 36 00 35 00 2d 00 32 00 45 00 2d 00 23 00 44 00 2d 00 23 00 44 00 2d 00 23 00 41 00 2d 00 32 00 34 00 2d 00 23 00 23 00 2d 00 23 00 23 00 2d 00 23 00 23 00 2d 00 23 00 23 00 2d } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}