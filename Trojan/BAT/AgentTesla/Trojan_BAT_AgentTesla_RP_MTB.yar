
rule Trojan_BAT_AgentTesla_RP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 17 8d 5d 00 00 01 25 16 1f 7c 9d 28 1f 01 00 06 0a 07 90 01 05 5a 90 01 05 61 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RP_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 1f 09 8d 44 00 00 01 25 d0 dc 00 00 04 28 c6 00 00 0a 0a 1f 0a 8d 44 00 00 01 25 d0 dd 00 00 04 28 c6 00 00 0a 0b } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RP_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {72 2b 0b 00 70 0b 28 df 00 00 0a 72 90 01 03 70 18 17 8d 21 00 00 01 25 16 07 72 90 01 03 70 72 90 01 03 70 6f 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RP_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {02 00 70 6f 90 01 01 00 00 0a 11 05 1f 16 5d 91 13 06 11 05 17 58 08 5d 90 00 } //01 00 
		$a_01_1 = {02 07 11 05 91 11 06 61 11 08 28 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RP_MTB_5{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 05 1f 16 5d 91 61 07 11 06 91 59 20 00 01 00 00 58 13 07 07 11 05 11 07 20 ff 00 00 00 5f 28 86 00 00 0a 9c 00 11 05 17 58 13 05 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RP_MTB_6{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {08 17 58 09 5d 13 06 07 08 07 08 91 11 04 08 1f 16 5d 91 61 07 11 06 91 59 20 00 01 00 00 58 20 ff 00 00 00 5f 28 b4 00 00 0a 9c 08 17 58 0c 08 09 32 cd } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RP_MTB_7{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 08 17 58 13 06 07 08 07 08 91 28 06 00 00 06 08 1f 16 5d 91 61 07 11 06 07 8e 69 5d 91 59 20 00 01 00 00 58 d2 9c 08 17 58 0c 00 08 09 fe 04 13 07 11 07 2d ca } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RP_MTB_8{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {00 07 08 07 08 91 28 0e 00 00 06 08 1f 16 5d 91 61 07 08 17 58 07 8e 69 5d 91 59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c 08 17 58 0c 00 08 07 8e 69 fe 04 13 05 11 05 2d c6 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RP_MTB_9{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {02 73 c7 00 00 06 25 6f c8 00 00 06 16 6a 6f 25 00 00 0a 25 25 6f c8 00 00 06 6f 2b 00 00 0a 69 6f c9 00 00 06 0a 6f cc 00 00 06 73 2b 00 00 06 28 4c 00 00 06 0b 73 2b 00 00 06 28 4b 00 00 06 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RP_MTB_10{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {fe 09 01 00 20 1f 00 00 00 8f 0c 00 00 01 25 47 20 7f 00 00 00 5f d2 52 fe 09 01 00 20 1f 00 00 00 8f 0c 00 00 01 25 47 20 40 00 00 00 60 d2 52 fe 09 01 00 20 00 00 00 00 8f 0c 00 00 01 25 47 20 f8 00 00 00 5f d2 52 2a } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RP_MTB_11{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {7f 01 00 00 04 7e 01 00 00 04 8e 69 28 0d 00 00 06 73 03 00 00 06 7e 03 00 00 04 7e 02 00 00 04 6f 02 00 00 06 7e 01 00 00 04 16 8f 17 00 00 01 7e 01 00 00 04 8e 69 1f 40 12 00 28 0c 00 00 06 26 16 0b 20 88 01 00 00 0c 16 16 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_AgentTesla_RP_MTB_12{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {11 07 8f 05 00 00 01 25 71 05 00 00 01 11 07 02 58 04 59 20 ff 00 00 00 5f d2 61 d2 81 05 00 00 01 11 12 1f 79 93 20 83 18 00 00 59 13 10 38 } //01 00 
		$a_01_1 = {61 02 61 0a 7e 1a 00 00 04 0c 08 74 03 00 00 1b 25 06 93 0b 06 18 58 93 07 61 0b 11 0f 20 a0 00 00 00 91 11 0f 1f 34 91 59 13 0e 38 } //00 00 
	condition:
		any of ($a_*)
 
}