
rule TrojanDownloader_O97M_Ursnif_AB_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.AB!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {26 20 22 5c [0-20] 2e 78 73 6c 22 } //1
		$a_01_1 = {22 61 70 70 64 61 74 61 22 } //1 "appdata"
		$a_03_2 = {3d 20 43 68 72 28 22 26 68 22 20 26 20 4d 69 64 28 [0-15] 2c 20 [0-15] 2c 20 32 29 29 } //1
		$a_01_3 = {3d 20 22 22 } //1 = ""
		$a_01_4 = {3d 20 4e 65 77 20 57 73 68 53 68 65 6c 6c } //1 = New WshShell
		$a_01_5 = {3d 20 45 6e 76 69 72 6f 6e 28 } //1 = Environ(
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}