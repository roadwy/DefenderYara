
rule TrojanDownloader_O97M_Encdoc_PVB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Encdoc.PVB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {45 58 45 43 28 22 70 6f 77 65 72 73 68 22 26 43 48 41 52 28 44 31 30 38 29 26 22 6c 6c 20 2d 77 20 31 20 28 6e 45 77 2d 6f 42 60 6a 65 63 54 } //1 EXEC("powersh"&CHAR(D108)&"ll -w 1 (nEw-oB`jecT
		$a_00_1 = {26 43 48 41 52 28 31 30 34 29 26 22 74 74 70 3a 2f 2f 75 72 67 66 75 69 64 2e 67 71 2f 7a 2f 7a 2e 65 78 65 } //1 &CHAR(104)&"ttp://urgfuid.gq/z/z.exe
		$a_00_2 = {44 22 26 43 48 41 52 28 31 30 31 29 26 22 73 74 69 6e 61 74 69 6f 6e 20 22 22 24 7b 65 6e 56 60 3a 61 70 70 64 61 74 61 7d } //1 D"&CHAR(101)&"stination ""${enV`:appdata}
		$a_00_3 = {62 79 70 61 73 73 20 53 74 61 72 22 26 43 48 41 52 28 31 31 36 29 26 22 2d 53 6c 65 22 26 43 48 41 52 28 44 31 30 38 29 26 22 70 20 32 35 } //1 bypass Star"&CHAR(116)&"-Sle"&CHAR(D108)&"p 25
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}