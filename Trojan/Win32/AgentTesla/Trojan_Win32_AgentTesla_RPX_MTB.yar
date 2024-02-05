
rule Trojan_Win32_AgentTesla_RPX_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {f7 e1 c1 ea 03 8d 14 52 03 d2 03 d2 8b c1 2b c2 8a 90 f8 91 40 00 30 14 31 41 3b cf 72 dd } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_AgentTesla_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/AgentTesla.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {ff d3 83 c4 0c 68 96 00 00 00 ff d6 83 ef 01 75 e6 bf 1e 00 00 00 90 90 6a 00 6a 00 68 90 01 04 ff d3 83 c4 0c 68 9b 00 00 00 ff d6 83 ef 01 75 e6 bf 0f 00 00 00 90 90 6a 00 6a 00 68 90 01 04 ff d3 83 c4 0c 68 9b 00 00 00 ff d6 83 ef 01 75 e6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_AgentTesla_RPX_MTB_3{
	meta:
		description = "Trojan:Win32/AgentTesla.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_01_0 = {38 00 30 00 2e 00 36 00 36 00 2e 00 37 00 35 00 2e 00 33 00 36 00 } //01 00 
		$a_01_1 = {61 00 73 00 2d 00 57 00 76 00 75 00 6e 00 6f 00 73 00 63 00 6b 00 65 00 2e 00 64 00 61 00 74 00 } //01 00 
		$a_01_2 = {45 6e 61 62 6c 65 41 63 63 6f 75 6e 74 } //01 00 
		$a_01_3 = {57 65 62 52 65 71 75 65 73 74 } //01 00 
		$a_01_4 = {53 6c 65 65 70 } //01 00 
		$a_01_5 = {52 61 74 65 41 63 63 6f 75 6e 74 } //01 00 
		$a_01_6 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } //01 00 
		$a_01_7 = {52 65 76 65 72 73 65 } //01 00 
		$a_01_8 = {48 74 74 70 57 65 62 52 65 71 75 65 73 74 } //01 00 
		$a_01_9 = {54 6f 41 72 72 61 79 } //00 00 
	condition:
		any of ($a_*)
 
}