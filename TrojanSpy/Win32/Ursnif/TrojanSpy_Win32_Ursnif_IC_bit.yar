
rule TrojanSpy_Win32_Ursnif_IC_bit{
	meta:
		description = "TrojanSpy:Win32/Ursnif.IC!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 5c 2e 5c 6d 61 69 6c 73 6c 6f 74 5c 6d 73 6c 30 } //01 00 
		$a_01_1 = {0f b7 0b c1 e9 0c 83 f9 03 74 17 83 f9 0a 75 27 0f b7 0b 81 e1 ff 0f 00 00 03 ce 01 01 11 51 04 } //01 00 
		$a_01_2 = {0f ba 26 1d 73 13 0f ba 26 1f 0f 92 c2 f6 da 1b d2 83 e2 20 83 c2 20 eb 1b 0f ba 26 1e 73 12 0f ba 26 1f 0f 92 c2 f6 da 1b d2 83 e2 02 42 42 eb 03 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Ursnif_IC_bit_2{
	meta:
		description = "TrojanSpy:Win32/Ursnif.IC!bit,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {8b 0a 83 c1 01 81 e1 fe 00 00 00 ff 34 ca e2 fb } //05 00 
		$a_03_1 = {8a 0e 0f b6 d0 0f b6 c9 33 d1 83 e2 0f c1 e8 04 33 04 95 90 01 04 c1 e9 04 8b d0 83 e2 0f 4f 33 ca c1 e8 04 46 33 04 8d 90 00 } //01 00 
		$a_03_2 = {8b 10 3b 55 90 01 01 75 0a 8b 50 04 3b 55 90 01 01 75 02 8b d8 83 c0 28 49 74 04 85 db 74 e5 90 00 } //01 00 
		$a_03_3 = {68 c8 04 00 00 50 89 44 24 28 89 44 24 2c 8d 44 24 30 50 83 cb ff c7 44 24 28 eb fe cc cc e8 90 01 04 83 c4 0c e8 90 01 04 8b f0 8d 44 24 08 50 ff 37 90 00 } //01 00 
		$a_03_4 = {2b ca 2b ce 81 c1 90 01 04 8b 41 04 2b 41 0c 03 01 3d 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}