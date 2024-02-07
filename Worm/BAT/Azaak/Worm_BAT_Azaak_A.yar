
rule Worm_BAT_Azaak_A{
	meta:
		description = "Worm:BAT/Azaak.A,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 07 00 00 0a 00 "
		
	strings :
		$a_01_0 = {5c 52 61 7a 76 61 6e 5c 44 65 73 6b 74 6f 70 5c 4f 68 20 79 65 61 68 5c 70 68 6f 74 6f 5c 70 68 6f 74 6f 5c 6f 62 6a 5c 44 65 62 75 67 5c 6c 65 61 67 75 65 6f 66 6c 65 67 65 6e 64 73 2e 70 64 62 } //05 00  \Razvan\Desktop\Oh yeah\photo\photo\obj\Debug\leagueoflegends.pdb
		$a_01_1 = {5c 00 61 00 75 00 74 00 6f 00 72 00 75 00 6e 00 2e 00 69 00 6e 00 66 00 } //05 00  \autorun.inf
		$a_01_2 = {73 00 68 00 65 00 6c 00 6c 00 65 00 78 00 65 00 63 00 75 00 74 00 65 00 3d 00 } //03 00  shellexecute=
		$a_01_3 = {5c 00 5c 00 4b 00 61 00 5a 00 61 00 41 00 5c 00 57 00 49 00 4e 00 4f 00 44 00 57 00 53 00 55 00 70 00 64 00 2e 00 65 00 78 00 65 00 } //01 00  \\KaZaA\WINODWSUpd.exe
		$a_01_4 = {5c 00 73 00 68 00 69 00 74 00 2e 00 62 00 6d 00 70 00 } //01 00  \shit.bmp
		$a_01_5 = {55 00 53 00 42 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //01 00  USBinstaller.exe
		$a_01_6 = {74 00 65 00 6d 00 70 00 6f 00 72 00 61 00 72 00 69 00 65 00 73 00 2e 00 65 00 78 00 65 00 } //00 00  temporaries.exe
		$a_00_7 = {5d 04 00 00 c4 71 03 80 5c 21 00 00 c6 } //71 03 
	condition:
		any of ($a_*)
 
}