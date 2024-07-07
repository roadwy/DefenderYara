
rule TrojanDownloader_O97M_Jerite_A{
	meta:
		description = "TrojanDownloader:O97M/Jerite.A,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4c 65 66 74 28 22 53 68 65 6c 6c 69 6e 73 68 61 6c 61 22 2c } //1 Left("Shellinshala",
		$a_01_1 = {4a 65 72 6b } //1 Jerk
		$a_01_2 = {53 70 72 69 74 65 } //1 Sprite
		$a_01_3 = {26 20 22 5c 73 22 20 26 20 22 65 2e 22 20 26 } //1 & "\s" & "e." &
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}