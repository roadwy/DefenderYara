
rule PWS_Win32_OnLineGames_NJ_sys{
	meta:
		description = "PWS:Win32/OnLineGames.NJ!sys,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_02_0 = {8b 40 08 68 53 53 44 54 c1 e0 02 50 56 ff 15 90 01 02 01 00 90 00 } //01 00 
		$a_00_1 = {5c 00 4b 00 6e 00 6f 00 77 00 6e 00 44 00 6c 00 6c 00 73 00 5c 00 4b 00 6e 00 6f 00 77 00 6e 00 44 00 6c 00 6c 00 50 00 61 00 74 00 68 00 } //01 00  \KnownDlls\KnownDllPath
		$a_00_2 = {5c 00 44 00 6f 00 73 00 44 00 65 00 76 00 69 00 63 00 65 00 73 00 5c 00 2a 00 3a 00 5c 00 } //01 00  \DosDevices\*:\
		$a_02_3 = {89 46 28 c6 46 20 00 c7 46 08 05 01 00 00 e8 90 01 02 00 00 89 46 50 8b 46 60 89 5e 64 83 e8 24 90 00 } //01 00 
		$a_02_4 = {33 c0 39 71 08 76 18 8b 4d 08 2b 8d 28 ff ff ff 01 0c 83 8b 0d 90 01 02 01 00 40 3b 41 08 72 e8 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}