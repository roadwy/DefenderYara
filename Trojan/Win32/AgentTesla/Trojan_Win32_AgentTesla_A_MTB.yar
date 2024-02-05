
rule Trojan_Win32_AgentTesla_A_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {64 ff 30 64 89 20 ff 05 90 01 03 00 75 90 01 01 83 3d 90 01 03 00 00 74 0a a1 90 01 03 00 e8 90 00 } //01 00 
		$a_02_1 = {8b c7 8b de 8b d3 90 05 10 01 90 e8 90 01 04 90 05 10 01 90 46 90 05 10 01 90 81 fe 90 01 02 00 00 75 90 00 } //01 00 
		$a_02_2 = {8b c8 03 ca 8b c2 b2 90 01 01 32 90 90 90 01 03 00 88 11 c3 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_AgentTesla_A_MTB_2{
	meta:
		description = "Trojan:Win32/AgentTesla.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 0a 00 "
		
	strings :
		$a_01_0 = {6e 6c 2e 4f 0e 53 43 29 7b bc 63 67 b2 6f 63 2f eb 17 06 8a 32 7f f1 13 5f d2 e1 47 39 d2 2b 3d 53 56 11 bf 10 ea 03 36 45 12 c7 4d 89 6c 25 ce } //01 00 
		$a_01_1 = {2e 76 6d 5f 73 65 63 } //01 00 
		$a_01_2 = {2e 74 68 65 6d 69 64 61 } //01 00 
		$a_01_3 = {43 00 68 00 6f 00 2d 00 43 00 68 00 75 00 6e 00 20 00 48 00 75 00 61 00 6e 00 67 00 } //01 00 
		$a_01_4 = {2f 63 68 65 63 6b 70 72 6f 74 65 63 74 69 6f 6e } //01 00 
		$a_01_5 = {65 00 2d 00 43 00 68 00 69 00 6e 00 61 00 20 00 50 00 65 00 74 00 72 00 6f 00 6c 00 65 00 75 00 6d 00 20 00 26 00 20 00 43 00 68 00 65 00 6d 00 69 00 63 00 61 00 6c 00 20 00 43 00 6f 00 72 00 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}