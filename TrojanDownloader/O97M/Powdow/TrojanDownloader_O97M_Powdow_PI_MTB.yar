
rule TrojanDownloader_O97M_Powdow_PI_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {63 47 39 33 5a 58 4a 7a 61 47 56 73 62 43 35 6c 65 47 55 67 4c 56 64 70 62 6d 52 76 64 31 4e 30 65 57 78 6c 49 45 68 70 5a 47 52 6c 62 } //1 cG93ZXJzaGVsbC5leGUgLVdpbmRvd1N0eWxlIEhpZGRlb
		$a_00_1 = {64 32 6c 75 62 57 64 74 64 48 4d 36 64 32 6c 75 4d 7a 4a 66 55 48 4a 76 59 32 56 7a 63 77 3d 3d } //1 d2lubWdtdHM6d2luMzJfUHJvY2Vzcw==
		$a_00_2 = {49 43 31 50 64 58 52 47 61 57 78 6c 49 45 4d 36 58 46 56 7a 5a 58 4a 7a 58 46 42 31 59 6d 78 70 59 31 78 45 62 32 4e 31 62 57 56 75 64 48 4e 63 5a 33 5a 6d 63 48 4a 68 65 6d 31 74 4c 6d 56 34 5a 58 30 } //1 IC1PdXRGaWxlIEM6XFVzZXJzXFB1YmxpY1xEb2N1bWVudHNcZ3ZmcHJhem1tLmV4ZX0
		$a_00_3 = {61 58 64 79 49 47 68 30 64 48 41 36 4c 79 38 30 4e 53 34 32 4e 69 34 79 4e 54 41 75 4d 54 41 78 4c 32 6c 55 4c 7a 45 31 4d 44 55 33 4f 44 41 75 61 6e 42 6e } //1 aXdyIGh0dHA6Ly80NS42Ni4yNTAuMTAxL2lULzE1MDU3ODAuanBn
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Powdow_PI_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PI!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_00_0 = {74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 37 7a 63 79 65 32 32 } //1 ttps://tinyurl.com/y7zcye22
		$a_00_1 = {2d 77 20 31 20 28 6e 45 77 2d 6f 42 60 6a 65 63 54 20 4e 65 74 } //1 -w 1 (nEw-oB`jecT Net
		$a_00_2 = {57 65 62 63 4c 60 49 45 4e 74 29 } //1 WebcL`IENt)
		$a_00_3 = {2d 77 20 31 20 2d 45 50 20 62 79 70 61 73 73 20 73 74 41 52 74 60 2d 73 6c 45 60 45 70 20 32 35 3b } //1 -w 1 -EP bypass stARt`-slE`Ep 25;
		$a_00_4 = {63 64 20 24 7b 65 6e 56 60 3a 61 70 70 64 61 74 61 7d 3b } //1 cd ${enV`:appdata};
		$a_00_5 = {45 58 45 43 28 43 48 41 52 28 31 31 32 29 26 43 48 41 52 28 31 31 31 29 26 43 48 41 52 28 31 31 39 29 26 43 48 41 52 28 31 30 31 29 26 43 48 41 52 28 31 31 34 29 26 43 48 41 52 28 31 31 35 29 26 43 48 41 52 28 31 30 34 29 26 43 48 41 52 28 31 30 31 29 26 43 48 41 52 28 31 30 38 29 26 43 48 41 52 28 31 30 38 29 26 } //1 EXEC(CHAR(112)&CHAR(111)&CHAR(119)&CHAR(101)&CHAR(114)&CHAR(115)&CHAR(104)&CHAR(101)&CHAR(108)&CHAR(108)&
		$a_00_6 = {64 61 64 61 64 61 64 61 66 61 66 61 66 61 66 61 } //1 dadadadafafafafa
		$a_00_7 = {75 73 65 6c 65 73 73 20 63 65 6c 6c } //1 useless cell
		$a_00_8 = {6d 61 67 69 63 20 63 65 6c 6c } //1 magic cell
		$a_00_9 = {65 70 69 63 20 63 65 6c 6c } //1 epic cell
		$a_02_10 = {28 27 2e 27 2b 27 2f ?? ?? 22 26 43 48 41 52 28 34 36 29 26 22 65 78 65 27 29 22 29 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_02_10  & 1)*1) >=11
 
}