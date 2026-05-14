
rule Trojan_BAT_AgentTesla_AJK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 1a 5d 16 fe 01 0d 09 2c 0b 02 08 02 08 91 1f 3d 61 b4 9c 00 00 08 17 d6 0c 08 07 31 e2 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_AgentTesla_AJK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 06 08 03 08 91 07 08 07 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 04 8e 69 fe 04 0d 09 2d e1 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_AgentTesla_AJK_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.AJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 1f 14 0a 73 e3 00 00 0a 0b 06 0c 17 0d 2b 0c 07 09 6f 12 02 00 0a 00 09 17 d6 0d 09 08 31 f0 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule Trojan_BAT_AgentTesla_AJK_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.AJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_81_0 = {24 61 31 62 32 63 33 64 34 2d 65 35 66 36 2d 34 37 61 38 2d 62 39 63 30 2d 64 31 65 32 66 33 61 34 62 35 63 36 } //2 $a1b2c3d4-e5f6-47a8-b9c0-d1e2f3a4b5c6
		$a_81_1 = {41 68 6f 72 63 61 64 6f 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } //2 Ahorcado.Properties.Resources
		$a_81_2 = {4a 75 65 67 6f 20 64 65 6c 20 41 68 6f 72 63 61 64 6f 20 2d 20 50 72 6f 79 65 63 74 6f 20 55 6e 69 76 65 72 73 69 74 61 72 69 6f } //2 Juego del Ahorcado - Proyecto Universitario
	condition:
		((#a_81_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2) >=6
 
}