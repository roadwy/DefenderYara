
rule TrojanDownloader_O97M_Ursnif_BD_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.BD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {2e 63 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 22 62 36 34 22 29 } //1 .createElement("b64")
		$a_01_1 = {28 22 34 36 65 73 61 62 2e 6e 69 62 22 29 } //1 ("46esab.nib")
		$a_01_2 = {44 65 62 75 67 2e 50 72 69 6e 74 20 45 72 72 6f 72 } //1 Debug.Print Error
		$a_01_3 = {3d 20 22 22 } //1 = ""
		$a_03_4 = {74 65 6d 70 5c [0-10] 2e 78 } //1
		$a_03_5 = {56 42 41 2e 49 6e 74 65 72 61 63 74 69 6f 6e ?? 2e 53 68 65 6c 6c 40 20 [0-10] 2c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}
rule TrojanDownloader_O97M_Ursnif_BD_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.BD!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {4f 70 65 6e 20 22 [0-10] 2e 78 22 20 2b 20 [0-10] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 } //1
		$a_01_1 = {2e 63 72 65 61 74 65 45 6c 65 6d 65 6e 74 28 22 62 36 34 22 29 } //1 .createElement("b64")
		$a_01_2 = {44 65 62 75 67 2e 50 72 69 6e 74 20 45 72 72 6f 72 } //1 Debug.Print Error
		$a_01_3 = {3d 20 22 22 } //1 = ""
		$a_01_4 = {3d 20 4e 65 77 20 57 73 68 53 68 65 6c 6c } //1 = New WshShell
		$a_03_5 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 [0-10] 29 90 0c 02 00 43 61 6c 6c 20 [0-10] 2e 65 78 65 63 28 [0-10] 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}