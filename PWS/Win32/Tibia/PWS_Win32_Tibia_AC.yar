
rule PWS_Win32_Tibia_AC{
	meta:
		description = "PWS:Win32/Tibia.AC,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 06 00 00 0a 00 "
		
	strings :
		$a_03_0 = {05 8d 34 b6 81 c6 90 01 02 62 00 90 09 16 00 b8 90 01 02 62 00 e8 90 01 02 ff ff 88 04 24 90 01 02 0f b6 c3 8b f0 c1 e6 90 00 } //0a 00 
		$a_03_1 = {ff 0f 1f 00 e8 90 09 04 00 50 6a 00 68 90 00 } //03 00 
		$a_03_2 = {7e 27 be 01 00 00 00 8d 45 f4 8b 55 fc 0f b6 54 32 ff 83 ea 03 e8 90 01 03 ff 8b 55 f4 8d 45 f8 e8 90 01 03 ff 46 4b 75 de 90 00 } //01 00 
		$a_00_3 = {52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } //01 00  ReadProcessMemory
		$a_00_4 = {4f 70 65 6e 50 72 6f 63 65 73 73 } //01 00  OpenProcess
		$a_00_5 = {47 65 74 57 69 6e 64 6f 77 54 68 72 65 61 64 50 72 6f 63 65 73 73 49 64 } //00 00  GetWindowThreadProcessId
	condition:
		any of ($a_*)
 
}