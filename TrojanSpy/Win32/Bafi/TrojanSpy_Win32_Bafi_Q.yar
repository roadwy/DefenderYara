
rule TrojanSpy_Win32_Bafi_Q{
	meta:
		description = "TrojanSpy:Win32/Bafi.Q,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 db 33 c0 99 8a 11 80 ca 20 03 c2 8d 49 02 66 39 19 75 90 01 01 3d e0 1e 00 00 75 90 01 01 c7 44 3c 90 01 01 01 00 00 80 c7 05 90 01 04 01 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Bafi_Q_2{
	meta:
		description = "TrojanSpy:Win32/Bafi.Q,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 11 80 ca 20 03 c2 90 8d 49 02 66 39 19 75 f0 3d e0 1e 00 00 75 5e c7 44 3c 1c 01 00 00 80 } //01 00 
		$a_00_1 = {00 61 64 6c 6c 2e 64 6c 6c 00 } //01 00 
		$a_00_2 = {00 43 6c 6f 73 65 47 75 61 72 64 00 } //01 00 
		$a_00_3 = {00 53 65 74 47 75 61 72 64 00 } //01 00 
		$a_00_4 = {84 c0 74 11 66 83 f8 61 7c 04 66 83 e8 20 03 d0 c1 c2 03 eb } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanSpy_Win32_Bafi_Q_3{
	meta:
		description = "TrojanSpy:Win32/Bafi.Q,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {3d 5a 35 4e d7 75 05 e8 90 01 01 00 00 00 b8 01 00 00 00 90 00 } //01 00 
		$a_03_1 = {81 39 8b ff 55 8b 75 08 8d 05 90 01 02 00 10 eb 0e 80 39 e9 74 2d 90 00 } //01 00 
		$a_03_2 = {81 39 8b ff 55 8b 90 02 02 75 08 8d 05 90 01 02 00 10 74 13 80 39 e9 74 32 90 00 } //01 00 
		$a_01_3 = {43 6c 6f 73 65 47 75 61 72 64 00 } //01 00 
		$a_01_4 = {53 65 74 47 75 61 72 64 00 } //01 00 
		$a_01_5 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 42 72 6f 77 73 65 72 20 48 65 6c 70 65 72 20 4f 62 6a 65 63 74 73 5c 00 } //00 00 
	condition:
		any of ($a_*)
 
}