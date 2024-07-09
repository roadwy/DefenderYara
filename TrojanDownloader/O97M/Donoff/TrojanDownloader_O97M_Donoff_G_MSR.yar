
rule TrojanDownloader_O97M_Donoff_G_MSR{
	meta:
		description = "TrojanDownloader:O97M/Donoff.G!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 65 74 73 28 22 76 4d 59 56 62 22 29 2e 43 65 6c 6c 73 28 31 33 34 2c 20 38 29 2e 56 61 6c 75 65 } //1 Sheets("vMYVb").Cells(134, 8).Value
		$a_01_1 = {53 68 65 6c 6c 20 4d 6f 68 61 69 72 } //1 Shell Mohair
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_G_MSR_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff.G!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 6b 61 70 69 73 6b 61 20 3d 20 45 6e 76 69 72 6f 6e 28 22 54 65 6d 22 20 26 20 22 70 22 29 } //1 skapiska = Environ("Tem" & "p")
		$a_03_1 = {70 6f 70 33 72 2e 52 75 6e 20 73 6b 61 70 69 73 6b 61 20 26 20 [0-09] 2e 54 61 67 2c 20 30 2c 20 46 61 6c 73 65 } //1
		$a_03_2 = {46 69 6c 65 43 6f 70 79 20 [0-09] 2e 4c 61 62 65 6c 31 2e 54 61 67 2c 20 73 6b 61 70 69 73 6b 61 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_G_MSR_3{
	meta:
		description = "TrojanDownloader:O97M/Donoff.G!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {26 20 22 43 22 20 26 20 43 68 72 28 35 32 29 20 26 20 22 41 22 20 26 20 43 68 72 28 28 56 61 6c 28 22 } //1 & "C" & Chr(52) & "A" & Chr((Val("
		$a_01_1 = {22 29 29 20 2b 20 36 38 29 20 26 20 22 77 22 20 26 20 43 68 72 28 28 4c 65 6e 28 22 41 4f 5c 22 29 20 2b 20 56 61 6c 28 22 } //1 ")) + 68) & "w" & Chr((Len("AO\") + Val("
		$a_01_2 = {29 20 2b 20 34 38 29 20 26 20 43 68 72 28 36 35 29 20 26 20 22 43 22 20 26 20 22 34 22 20 26 20 43 68 72 28 36 35 29 20 26 20 22 56 22 } //1 ) + 48) & Chr(65) & "C" & "4" & Chr(65) & "V"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}