
rule TrojanDownloader_O97M_Powdow_PF_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 0a 00 00 01 00 "
		
	strings :
		$a_00_0 = {64 6f 6e 74 20 74 65 73 74 20 6d 65 } //01 00  dont test me
		$a_00_1 = {61 61 61 61 61 61 61 6c 61 6c 61 6c 61 61 } //01 00  aaaaaaalalalaa
		$a_00_2 = {75 73 65 6c 65 73 73 20 63 65 6c 6c } //01 00  useless cell
		$a_00_3 = {6d 61 67 69 63 20 63 65 6c 6c } //01 00  magic cell
		$a_00_4 = {65 70 69 63 20 63 65 6c 6c } //01 00  epic cell
		$a_00_5 = {6f 6b 6f 6b 6f 6b 6f } //01 00  okokoko
		$a_00_6 = {43 48 41 52 28 31 31 32 29 26 43 48 41 52 28 31 31 31 29 26 22 77 65 72 73 68 65 22 26 43 48 41 52 28 31 30 38 29 26 43 48 41 52 28 31 30 38 29 26 43 48 41 52 28 33 32 29 26 } //01 00  CHAR(112)&CHAR(111)&"wershe"&CHAR(108)&CHAR(108)&CHAR(32)&
		$a_00_7 = {2d 77 20 31 20 2d 45 50 20 62 79 70 61 73 73 20 73 74 41 52 74 60 2d 73 6c 45 60 45 70 20 32 35 } //01 00  -w 1 -EP bypass stARt`-slE`Ep 25
		$a_00_8 = {63 64 20 24 7b 65 6e 56 60 3a 61 70 70 64 61 74 61 7d } //01 00  cd ${enV`:appdata}
		$a_00_9 = {28 27 2e 27 2b 27 2f 61 6c 22 26 43 48 41 52 28 34 36 29 26 22 65 78 65 27 29 } //00 00  ('.'+'/al"&CHAR(46)&"exe')
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Powdow_PF_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PF!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 47 39 33 5a 58 4a 7a 61 47 56 73 62 43 35 6c 65 47 55 67 4c 56 64 70 62 6d 52 76 64 31 4e 30 65 57 78 6c 49 45 68 70 5a 47 52 6c 62 } //01 00  cG93ZXJzaGVsbC5leGUgLVdpbmRvd1N0eWxlIEhpZGRlb
		$a_00_1 = {64 32 6c 75 62 57 64 74 64 48 4d 36 64 32 6c 75 4d 7a 4a 66 55 48 4a 76 59 32 56 7a 63 77 3d 3d } //01 00  d2lubWdtdHM6d2luMzJfUHJvY2Vzcw==
		$a_00_2 = {51 7a 70 63 56 58 4e 6c 63 6e 4e 63 55 48 56 69 62 47 6c 6a 58 45 52 76 59 33 56 74 5a 57 35 30 63 31 78 35 5a 57 52 33 64 33 42 7a 61 47 34 75 5a 58 68 6c } //01 00  QzpcVXNlcnNcUHVibGljXERvY3VtZW50c1x5ZWR3d3BzaG4uZXhl
		$a_00_3 = {61 58 64 79 49 47 68 30 64 48 41 36 4c 79 38 30 4e 53 34 32 4e 69 34 79 4e 54 41 75 4d 54 41 78 4c 32 6c 55 4c 30 52 47 53 53 30 32 4d 44 45 33 4e 79 35 71 63 47 63 67 4c 55 39 31 64 45 } //01 00  aXdyIGh0dHA6Ly80NS42Ni4yNTAuMTAxL2lUL0RGSS02MDE3Ny5qcGcgLU91dE
		$a_00_4 = {55 33 52 68 63 6e 51 74 55 48 4a 76 59 32 56 7a 63 79 41 74 52 6d 6c 73 5a 56 42 68 64 47 67 } //00 00  U3RhcnQtUHJvY2VzcyAtRmlsZVBhdGg
	condition:
		any of ($a_*)
 
}