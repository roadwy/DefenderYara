
rule PWS_Win32_OnLineGames_Z{
	meta:
		description = "PWS:Win32/OnLineGames.Z,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {ff d6 8d 8c 24 28 01 00 00 68 04 01 00 00 51 ff d6 8b 35 38 20 40 00 8d 54 24 24 68 a0 30 40 00 52 ff d6 8b f8 8d 84 24 28 01 00 00 68 90 30 40 00 50 89 7c 24 24 ff d6 8d 4c 24 10 89 44 24 20 51 68 06 00 02 00 6a 00 68 60 30 40 00 68 02 00 00 80 ff 15 08 20 40 00 8b 35 00 20 40 00 85 c0 74 07 8b 54 24 10 52 ff d6 } //01 00 
		$a_00_1 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //01 00  SOFTWARE\Microsoft\Windows\CurrentVersion\Run
		$a_00_2 = {6b 61 72 6e 65 6c 33 32 2e 64 6c 6c } //01 00  karnel32.dll
		$a_00_3 = {4b 61 72 74 53 76 72 2e 65 78 65 } //00 00  KartSvr.exe
	condition:
		any of ($a_*)
 
}