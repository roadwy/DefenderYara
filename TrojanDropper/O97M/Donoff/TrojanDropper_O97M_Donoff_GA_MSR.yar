
rule TrojanDropper_O97M_Donoff_GA_MSR{
	meta:
		description = "TrojanDropper:O97M/Donoff.GA!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_02_0 = {46 75 6e 63 74 69 6f 6e 20 [0-0d] 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 4c 6f 61 64 4c 69 62 72 61 72 79 41 22 20 28 42 79 56 61 6c 20 [0-11] 20 41 73 20 53 74 72 69 6e 67 29 20 41 73 20 4c 6f 6e 67 50 74 72 } //2
		$a_00_1 = {66 6f 6c 64 65 72 70 61 74 68 20 3d 20 22 43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 57 50 53 4f 66 66 69 63 65 } //2 folderpath = "C:\ProgramData\WPSOffice
		$a_00_2 = {6c 6f 61 64 65 72 70 61 74 68 20 3d 20 66 6f 6c 64 65 72 70 61 74 68 20 26 20 22 5c 77 70 73 6f 66 66 69 63 65 5f 61 61 6d 2e 6f 63 78 } //2 loaderpath = folderpath & "\wpsoffice_aam.ocx
		$a_00_3 = {45 78 74 72 61 63 74 4c 6f 61 64 65 72 20 28 6c 6f 61 64 65 72 70 61 74 68 29 } //1 ExtractLoader (loaderpath)
		$a_00_4 = {74 63 75 65 6f 6d 79 6c 61 6c 62 6f 20 28 6c 6f 61 64 65 72 70 61 74 68 29 } //1 tcueomylalbo (loaderpath)
	condition:
		((#a_02_0  & 1)*2+(#a_00_1  & 1)*2+(#a_00_2  & 1)*2+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=7
 
}