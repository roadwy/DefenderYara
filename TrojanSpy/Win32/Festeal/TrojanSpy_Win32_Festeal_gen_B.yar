
rule TrojanSpy_Win32_Festeal_gen_B{
	meta:
		description = "TrojanSpy:Win32/Festeal.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {74 32 ff 35 90 01 04 e8 90 01 02 00 00 3b c3 74 0c 8b 40 0c 8b 00 8b 00 a3 90 01 04 33 c0 68 90 01 04 40 e8 90 01 02 00 00 85 c0 59 74 90 01 01 a1 90 01 04 39 90 00 } //01 00 
		$a_02_1 = {66 83 fd 19 74 0c 66 83 fd 50 74 06 66 83 fd 6e 75 13 ff 74 24 10 ff 15 90 01 02 40 00 85 db 74 3a 0f b7 c5 eb 29 90 00 } //01 00 
		$a_02_2 = {66 83 fd 19 0f b7 f8 74 0c 66 83 fd 50 74 06 66 83 fd 6e 75 14 8b 4c 24 10 51 ff 15 90 01 03 00 85 f6 74 34 0f b7 c5 eb 24 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}