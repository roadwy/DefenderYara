
rule TrojanDownloader_O97M_Ursnif_OJP_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.OJP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 65 6c 69 6d 69 6e 61 6e 6f 28 22 39 20 48 2f 31 31 63 56 20 54 33 20 35 73 38 74 61 4f 72 36 74 20 22 2c 20 31 29 } //1 = eliminano("9 H/11cV T3 5s8taOr6t ", 1)
		$a_01_1 = {65 6c 69 6d 69 6e 61 6e 6f 28 22 37 20 4a 20 38 72 75 4e 39 6e 64 35 34 6c 6c 4b 22 2c 20 33 29 20 26 20 33 32 20 26 20 } //1 eliminano("7 J 8ruN9nd54llK", 3) & 32 & 
		$a_01_2 = {26 20 65 6c 69 6d 69 6e 61 6e 6f 28 22 38 5c 41 63 4e 34 42 61 4a 38 6c 30 63 35 33 32 2e 38 65 59 78 45 37 65 31 22 2c 20 33 29 } //1 & eliminano("8\AcN4BaJ8l0c532.8eYxE7e1", 3)
		$a_01_3 = {28 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 73 68 65 6c 6c 22 29 2e 65 78 65 63 28 45 78 65 6c 29 2e 53 74 64 4f 75 74 2e 52 65 61 64 41 6c 6c 28 29 29 3a 20 57 6f 72 6b 62 6f 6f 6b 73 2e 41 70 70 6c 69 63 61 74 69 6f 6e 2e 44 69 73 70 6c 61 79 41 6c 65 72 74 73 20 3d 20 46 61 6c 73 65 3a 20 41 70 70 6c 69 63 61 74 69 6f 6e 2e 51 75 69 74 } //1 (CreateObject("wscript.shell").exec(Exel).StdOut.ReadAll()): Workbooks.Application.DisplayAlerts = False: Application.Quit
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}