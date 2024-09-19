
rule Trojan_BAT_AgentTesla_RP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {5f d2 13 0f 11 06 11 0f 95 d2 13 10 11 13 20 ?? ?? ?? ?? 5a 20 ?? ?? ?? ?? 61 38 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_RP_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 17 8d 5d 00 00 01 25 16 1f 7c 9d 28 1f 01 00 06 0a 07 ?? ?? ?? ?? ?? 5a ?? ?? ?? ?? ?? 61 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_RP_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 1f 09 8d 44 00 00 01 25 d0 dc 00 00 04 28 c6 00 00 0a 0a 1f 0a 8d 44 00 00 01 25 d0 dd 00 00 04 28 c6 00 00 0a 0b } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_RP_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 73 1a 00 00 06 0a 00 06 17 6f 26 00 00 06 00 06 17 6f 23 00 00 0a 00 00 de 0b 06 2c 07 06 6f 24 00 00 0a 00 dc 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_RP_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {72 2b 0b 00 70 0b 28 df 00 00 0a 72 ?? ?? ?? 70 18 17 8d 21 00 00 01 25 16 07 72 ?? ?? ?? 70 72 ?? ?? ?? 70 6f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_RP_MTB_6{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {02 00 70 6f ?? 00 00 0a 11 05 1f 16 5d 91 13 06 11 05 17 58 08 5d } //1
		$a_01_1 = {02 07 11 05 91 11 06 61 11 08 28 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_RP_MTB_7{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 05 1f 16 5d 91 61 07 11 06 91 59 20 00 01 00 00 58 13 07 07 11 05 11 07 20 ff 00 00 00 5f 28 86 00 00 0a 9c 00 11 05 17 58 13 05 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_RP_MTB_8{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 0c 00 00 06 28 03 00 00 06 2a 00 13 30 06 00 ?? ?? 00 00 02 00 00 11 d0 01 00 00 02 28 } //1
		$a_01_1 = {73 65 74 5f 50 61 64 64 69 6e 67 } //1 set_Padding
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_BAT_AgentTesla_RP_MTB_9{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 17 58 09 5d 13 06 07 08 07 08 91 11 04 08 1f 16 5d 91 61 07 11 06 91 59 20 00 01 00 00 58 20 ff 00 00 00 5f 28 b4 00 00 0a 9c 08 17 58 0c 08 09 32 cd } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_RP_MTB_10{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 08 17 58 13 06 07 08 07 08 91 28 06 00 00 06 08 1f 16 5d 91 61 07 11 06 07 8e 69 5d 91 59 20 00 01 00 00 58 d2 9c 08 17 58 0c 00 08 09 fe 04 13 07 11 07 2d ca } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_RP_MTB_11{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 72 00 00 06 0a 06 02 7d 42 00 00 04 16 06 7b 42 00 00 04 6f 9d 00 00 0a 18 5b 28 a7 00 00 0a 06 fe 06 73 00 00 06 73 a8 00 00 0a 28 01 00 00 2b 28 02 00 00 2b 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_RP_MTB_12{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 07 08 07 08 91 28 0e 00 00 06 08 1f 16 5d 91 61 07 08 17 58 07 8e 69 5d 91 59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c 08 17 58 0c 00 08 07 8e 69 fe 04 13 05 11 05 2d c6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_RP_MTB_13{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 73 c7 00 00 06 25 6f c8 00 00 06 16 6a 6f 25 00 00 0a 25 25 6f c8 00 00 06 6f 2b 00 00 0a 69 6f c9 00 00 06 0a 6f cc 00 00 06 73 2b 00 00 06 28 4c 00 00 06 0b 73 2b 00 00 06 28 4b 00 00 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_RP_MTB_14{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {67 65 74 5f 4d 61 72 63 61 } //1 get_Marca
		$a_01_1 = {73 65 74 5f 50 72 65 63 69 6f } //1 set_Precio
		$a_01_2 = {67 65 74 5f 43 6f 64 69 67 6f } //1 get_Codigo
		$a_01_3 = {67 65 74 5f 4e 6f 6d 62 72 65 } //1 get_Nombre
		$a_01_4 = {02 07 11 05 91 11 06 61 11 08 28 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule Trojan_BAT_AgentTesla_RP_MTB_15{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 09 01 00 20 1f 00 00 00 8f 0c 00 00 01 25 47 20 7f 00 00 00 5f d2 52 fe 09 01 00 20 1f 00 00 00 8f 0c 00 00 01 25 47 20 40 00 00 00 60 d2 52 fe 09 01 00 20 00 00 00 00 8f 0c 00 00 01 25 47 20 f8 00 00 00 5f d2 52 2a } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_RP_MTB_16{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7f 01 00 00 04 7e 01 00 00 04 8e 69 28 0d 00 00 06 73 03 00 00 06 7e 03 00 00 04 7e 02 00 00 04 6f 02 00 00 06 7e 01 00 00 04 16 8f 17 00 00 01 7e 01 00 00 04 8e 69 1f 40 12 00 28 0c 00 00 06 26 16 0b 20 88 01 00 00 0c 16 16 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_BAT_AgentTesla_RP_MTB_17{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 07 8f 05 00 00 01 25 71 05 00 00 01 11 07 02 58 04 59 20 ff 00 00 00 5f d2 61 d2 81 05 00 00 01 11 12 1f 79 93 20 83 18 00 00 59 13 10 38 } //1
		$a_01_1 = {61 02 61 0a 7e 1a 00 00 04 0c 08 74 03 00 00 1b 25 06 93 0b 06 18 58 93 07 61 0b 11 0f 20 a0 00 00 00 91 11 0f 1f 34 91 59 13 0e 38 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}