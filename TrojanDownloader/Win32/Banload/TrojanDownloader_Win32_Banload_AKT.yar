
rule TrojanDownloader_Win32_Banload_AKT{
	meta:
		description = "TrojanDownloader:Win32/Banload.AKT,SIGNATURE_TYPE_PEHSTR_EXT,54 01 40 01 09 00 00 64 00 "
		
	strings :
		$a_03_0 = {2f 6e 69 63 68 61 6e 90 01 01 2e 7a 69 70 00 90 00 } //64 00 
		$a_01_1 = {2f 61 72 71 61 2e 62 6d 70 00 } //64 00 
		$a_01_2 = {64 6f 6d 69 6e 69 6f 74 65 6d 70 6f 72 61 72 69 6f 2e 63 6f 6d } //c8 00  dominiotemporario.com
		$a_01_3 = {64 6c 2e 64 72 6f 70 62 6f 78 2e 63 6f 6d 2f 75 2f 37 34 36 34 37 39 36 30 } //14 00  dl.dropbox.com/u/74647960
		$a_01_4 = {43 4d 44 20 2f 43 20 43 6f 70 79 00 } //14 00  䵃⁄䌯䌠灯y
		$a_01_5 = {46 61 6c 68 61 21 21 21 20 41 72 71 75 69 76 6f 20 } //14 00  Falha!!! Arquivo 
		$a_01_6 = {62 69 67 6d 61 63 2e 65 78 65 00 } //14 00 
		$a_01_7 = {72 65 61 72 64 65 72 2e 65 78 65 00 } //14 00 
		$a_01_8 = {00 63 72 66 72 73 2e 65 78 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}