
rule Trojan_Win32_Trickbot_B_MTB{
	meta:
		description = "Trojan:Win32/Trickbot.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {89 7d f0 83 ef 01 89 45 ec 8b 45 f0 0f af c7 83 e0 01 83 f8 00 0f 94 c0 83 fb 0a 0f 9c c4 08 e0 a8 01 } //01 00 
		$a_01_1 = {0f b6 f0 8a 44 24 1e 0f b6 f8 89 f8 31 f0 88 44 24 1e } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Trickbot_B_MTB_2{
	meta:
		description = "Trojan:Win32/Trickbot.B!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 61 6e 64 6c 65 72 00 64 70 6f 73 74 00 00 00 69 6e 66 65 63 74 } //01 00 
		$a_01_1 = {5c 73 76 63 63 74 6c } //01 00 
		$a_01_2 = {30 31 32 33 34 35 36 37 38 39 5f 71 77 65 72 74 79 75 69 6f 70 61 73 64 66 67 68 6a 6b 6c 7a 78 63 76 62 6e 6d } //01 00 
		$a_01_3 = {30 00 31 00 32 00 33 00 34 00 35 00 36 00 37 00 38 00 39 00 5f 00 71 00 77 00 65 00 72 00 74 00 79 00 75 00 69 00 6f 00 70 00 61 00 73 00 64 00 66 00 67 00 68 00 6a 00 6b 00 6c 00 7a 00 78 00 63 00 76 00 62 00 6e 00 6d 00 } //01 00 
		$a_01_4 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //00 00 
	condition:
		any of ($a_*)
 
}