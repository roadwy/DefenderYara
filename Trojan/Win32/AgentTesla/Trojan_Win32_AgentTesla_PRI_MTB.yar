
rule Trojan_Win32_AgentTesla_PRI_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.PRI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {8b 45 f8 83 c0 01 89 45 f8 8b 4d f8 3b 4d ec 73 47 8b 55 f0 03 55 f8 8a 02 88 45 ff 8b 4d c8 03 4d e8 8a 11 88 55 fe 0f b6 45 ff c1 f8 03 0f b6 4d ff c1 e1 05 0b c1 0f b6 55 fe 33 c2 8b 4d f0 03 4d f8 88 01 8b 45 e8 83 c0 01 99 b9 0c 00 00 00 f7 f9 89 55 e8 eb a8 } //01 00 
		$a_01_1 = {4a 4b 62 74 67 64 66 64 } //01 00 
		$a_01_2 = {47 65 74 54 65 6d 70 50 61 74 68 41 } //01 00 
		$a_01_3 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00 
	condition:
		any of ($a_*)
 
}