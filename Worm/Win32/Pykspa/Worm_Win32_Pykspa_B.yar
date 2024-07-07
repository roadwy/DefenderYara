
rule Worm_Win32_Pykspa_B{
	meta:
		description = "Worm:Win32/Pykspa.B,SIGNATURE_TYPE_PEHSTR_EXT,24 00 23 00 0f 00 00 "
		
	strings :
		$a_00_0 = {65 63 68 6f 31 32 33 } //10 echo123
		$a_01_1 = {53 6b 79 75 69 6a 68 73 64 73 64 2d 41 50 49 2d 43 64 64 72 2d } //10 Skyuijhsdsd-API-Cddr-
		$a_01_2 = {53 6b 79 70 65 43 6f 6e 74 72 6f 6c 41 50 49 41 74 74 61 63 68 } //10 SkypeControlAPIAttach
		$a_00_3 = {63 68 75 6a 2e 65 78 65 } //1 chuj.exe
		$a_00_4 = {64 72 6e 6e 63 74 6f 70 2e 65 78 65 } //1 drnnctop.exe
		$a_00_5 = {64 69 64 65 6c 69 5f 70 61 70 61 69 2e 73 63 72 } //1 dideli_papai.scr
		$a_00_6 = {53 6f 61 70 20 42 75 62 62 6c 65 73 2e 62 6d 70 } //1 Soap Bubbles.bmp
		$a_01_7 = {25 64 2e 25 64 2e 25 64 2e 25 64 20 64 6f 77 6e 6c 6f 61 64 25 64 2e 61 76 61 73 74 2e 63 6f 6d } //1 %d.%d.%d.%d download%d.avast.com
		$a_00_8 = {68 6f 77 20 61 72 65 20 75 20 3f } //1 how are u ?
		$a_00_9 = {74 68 69 73 20 28 68 61 70 70 79 29 20 73 65 78 79 20 6f 6e 65 } //1 this (happy) sexy one
		$a_00_10 = {77 68 65 72 65 20 49 20 70 75 74 20 75 72 20 70 68 6f 74 6f } //1 where I put ur photo
		$a_00_11 = {79 6f 75 72 20 70 68 6f 74 6f 73 20 6c 6f 6f 6b 73 20 72 65 61 6c 79 20 6e 69 63 65 } //1 your photos looks realy nice
		$a_00_12 = {77 68 61 74 20 75 72 20 66 72 69 65 6e 64 20 6e 61 6d 65 20 77 69 63 68 20 69 73 20 69 6e 20 70 68 6f 74 6f 20 3f } //1 what ur friend name wich is in photo ?
		$a_00_13 = {6f 6f 70 73 20 73 6f 72 72 79 20 70 6c 65 61 73 65 20 64 6f 6e 27 74 20 6c 6f 6f 6b 20 74 68 65 72 65 } //1 oops sorry please don't look there
		$a_00_14 = {6c 6f 6f 6b 20 77 68 61 74 20 63 72 61 7a 79 20 70 68 6f 74 6f 20 54 69 66 66 61 6e 79 20 73 65 6e 74 20 74 6f 20 6d 65 2c 6c 6f 6f 6b 73 20 63 6f 6f 6c } //1 look what crazy photo Tiffany sent to me,looks cool
	condition:
		((#a_00_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_01_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_00_13  & 1)*1+(#a_00_14  & 1)*1) >=35
 
}