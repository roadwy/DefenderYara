
rule TrojanSpy_Win32_Banbra_M{
	meta:
		description = "TrojanSpy:Win32/Banbra.M,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {3e 3e 20 42 61 6e 6b 20 4e 61 6d 65 20 2d 20 00 3e 3e 20 43 6c 69 70 42 6f 61 72 64 20 2d 20 00 } //02 00 
		$a_01_1 = {21 4d 63 2e 41 66 65 65 21 00 } //01 00 
		$a_01_2 = {26 63 6f 6e 74 65 6e 74 32 3d 00 } //01 00 
		$a_01_3 = {6b 65 79 2e 6c 6f 67 } //00 00  key.log
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Banbra_M_2{
	meta:
		description = "TrojanSpy:Win32/Banbra.M,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {28 6a 73 6e 00 00 00 00 67 7c 67 78 6c 69 7a 72 39 32 26 6e 6e 66 00 00 } //01 00 
		$a_03_1 = {8a 55 fb 8a 14 17 80 e2 0a 32 c2 33 d2 8a d3 8a 14 16 80 e2 f0 80 e2 f0 02 d0 33 c0 8a c3 8b 4d fc 88 14 01 fe 45 fb 90 02 10 33 d2 8a 55 fb 3b c2 90 01 01 04 c6 45 fb 00 43 fe 4d fa 75 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}