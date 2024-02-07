
rule Trojan_Win32_JackServn_C_bit{
	meta:
		description = "Trojan:Win32/JackServn.C!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 02 00 "
		
	strings :
		$a_03_0 = {b1 2d 0f be c9 51 b1 5f 0f be d1 52 b1 77 0f be c9 51 0f be d3 52 b1 6e 0f be c9 51 b0 25 0f be c0 50 b1 2f 0f be d1 52 50 b0 65 0f be c0 50 b0 6d 0f be c8 b0 73 51 0f be d0 52 68 90 01 03 00 81 c6 1c 01 00 00 56 e8 90 01 03 ff 90 00 } //02 00 
		$a_01_1 = {44 30 37 46 35 38 37 31 43 38 38 39 41 30 38 38 46 44 43 41 42 41 39 36 32 38 30 30 33 32 30 33 } //01 00  D07F5871C889A088FDCABA9628003203
		$a_01_2 = {25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 } //01 00  %c%c%c%c%c%c%c%c%c%c
		$a_01_3 = {6b 69 6c 6c 66 69 6c 65 2e 62 61 74 } //01 00  killfile.bat
		$a_01_4 = {25 73 5c 25 73 2e 65 78 65 } //00 00  %s\%s.exe
	condition:
		any of ($a_*)
 
}