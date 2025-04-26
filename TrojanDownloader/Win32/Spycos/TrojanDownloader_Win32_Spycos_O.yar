
rule TrojanDownloader_Win32_Spycos_O{
	meta:
		description = "TrojanDownloader:Win32/Spycos.O,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6f 6b 20 64 6f 77 6c 6f 61 64 65 64 20 63 6f 6e 66 69 67 20 00 } //2
		$a_01_1 = {64 6f 77 6c 6f 61 64 20 63 6f 6e 66 69 67 20 69 73 20 66 61 69 6c 20 00 } //2
		$a_01_2 = {6f 6b 20 64 6f 77 6c 6f 61 64 65 64 20 64 6c 6c 20 00 } //2 歯搠睯潬摡摥搠汬 
		$a_01_3 = {67 56 4e 68 43 44 33 47 6e 72 59 6a 6e 41 4b 33 58 4a 53 72 46 41 } //1 gVNhCD3GnrYjnAK3XJSrFA
		$a_01_4 = {4d 35 53 65 31 56 53 51 43 37 43 6c 2f 32 30 39 47 4a 75 4d 76 4d 36 66 70 } //1 M5Se1VSQC7Cl/209GJuMvM6fp
		$a_01_5 = {49 4e 4f 56 41 4e 44 4f 4f 4f 4f 2e 2e 2e 00 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}