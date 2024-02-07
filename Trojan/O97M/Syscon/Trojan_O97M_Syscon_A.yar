
rule Trojan_O97M_Syscon_A{
	meta:
		description = "Trojan:O97M/Syscon.A,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {6e 52 65 73 75 6c 74 20 3d 20 53 68 65 6c 6c 28 22 63 6d 64 20 2f 63 20 65 78 70 61 6e 64 20 25 54 45 4d 50 25 5c 73 65 74 75 70 2e 63 61 62 20 2d 46 3a 2a } //01 00  nResult = Shell("cmd /c expand %TEMP%\setup.cab -F:*
		$a_02_1 = {26 26 20 64 65 6c 20 2f 66 20 2f 71 90 02 10 73 65 74 75 70 2e 63 61 62 20 26 26 90 00 } //01 00 
		$a_00_2 = {47 65 74 4f 62 6a 65 63 74 28 22 57 69 6e 6d 67 6d 74 73 3a 22 29 2e 45 78 65 63 51 75 65 72 79 } //01 00  GetObject("Winmgmts:").ExecQuery
		$a_00_3 = {49 73 57 69 6e 33 32 4f 72 57 69 6e 36 34 20 3d 20 22 57 69 6e 22 20 26 20 69 6e 66 6f 2e 41 64 64 72 65 73 73 57 69 64 74 68 } //01 00  IsWin32OrWin64 = "Win" & info.AddressWidth
		$a_00_4 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } //00 00  Sub Document_Open()
		$a_00_5 = {5d 04 00 00 } //da a9 
	condition:
		any of ($a_*)
 
}