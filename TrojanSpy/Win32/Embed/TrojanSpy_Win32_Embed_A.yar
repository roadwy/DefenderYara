
rule TrojanSpy_Win32_Embed_A{
	meta:
		description = "TrojanSpy:Win32/Embed.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 04 00 "
		
	strings :
		$a_01_0 = {66 66 6e 6f 73 7c 26 74 6d 2a 2a 2c 4c 30 46 47 } //01 00 
		$a_01_1 = {4d 00 63 00 61 00 66 00 65 00 65 00 20 00 46 00 72 00 61 00 6d 00 65 00 57 00 6f 00 72 00 6b 00 20 00 3a 00 28 00 } //01 00 
		$a_01_2 = {48 74 74 70 5f 64 6c 6c 2e 64 6c 6c 00 } //01 00 
		$a_01_3 = {50 6c 61 79 57 6f 72 6b 00 } //01 00 
		$a_01_4 = {57 69 6e 73 33 32 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Embed_A_2{
	meta:
		description = "TrojanSpy:Win32/Embed.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 06 00 00 02 00 "
		
	strings :
		$a_01_0 = {f3 a5 8d 48 02 b8 ab aa aa aa f7 e1 d1 ea a4 8d 04 52 89 45 f0 } //02 00 
		$a_01_1 = {6a 04 50 56 c7 44 24 30 d4 c3 b2 a1 ff d7 } //02 00 
		$a_01_2 = {68 88 13 00 00 ff d6 8d 4c 24 08 6a 00 51 ff d7 85 c0 74 ec 68 10 27 00 00 } //01 00 
		$a_01_3 = {48 74 74 70 5f 64 6c 6c 2e 64 6c 6c 00 } //01 00 
		$a_01_4 = {50 6c 61 79 57 6f 72 6b 00 } //01 00 
		$a_01_5 = {57 69 6e 73 33 32 00 } //00 00 
	condition:
		any of ($a_*)
 
}