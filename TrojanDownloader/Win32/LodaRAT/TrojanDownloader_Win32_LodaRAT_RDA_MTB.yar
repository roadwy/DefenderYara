
rule TrojanDownloader_Win32_LodaRAT_RDA_MTB{
	meta:
		description = "TrojanDownloader:Win32/LodaRAT.RDA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_01_0 = {25 00 77 00 69 00 6e 00 64 00 69 00 72 00 25 00 5c 00 73 00 76 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 } //1 %windir%\svhost.exe
		$a_01_1 = {2f 00 2f 00 61 00 70 00 70 00 2e 00 63 00 73 00 76 00 68 00 6f 00 73 00 74 00 2e 00 69 00 6e 00 66 00 6f 00 2f 00 6c 00 6f 00 61 00 64 00 65 00 72 00 2f 00 73 00 70 00 6f 00 6f 00 6c 00 73 00 76 00 2e 00 74 00 6d 00 70 00 } //1 //app.csvhost.info/loader/spoolsv.tmp
		$a_01_2 = {0f b6 04 39 33 c6 25 ff 00 00 00 c1 ee 08 33 b4 85 fc fb ff ff 41 } //2
		$a_01_3 = {0f b6 c2 03 c8 81 e1 ff 00 00 00 0f b6 84 0d fc fe ff ff 8b 8d f4 fe ff ff 30 44 39 ff } //2
		$a_01_4 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 33 00 70 00 63 00 36 00 52 00 57 00 4f 00 67 00 65 00 63 00 74 00 47 00 54 00 46 00 71 00 43 00 6f 00 77 00 78 00 6a 00 65 00 47 00 79 00 33 00 58 00 49 00 47 00 50 00 74 00 4c 00 77 00 4e 00 72 00 73 00 72 00 32 00 7a 00 44 00 63 00 74 00 59 00 44 00 34 00 68 00 41 00 55 00 35 00 70 00 6a 00 34 00 47 00 57 00 37 00 72 00 6d 00 38 00 67 00 48 00 72 00 48 00 79 00 54 00 42 00 36 00 } //1 Global\3pc6RWOgectGTFqCowxjeGy3XIGPtLwNrsr2zDctYD4hAU5pj4GW7rm8gHrHyTB6
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1) >=7
 
}