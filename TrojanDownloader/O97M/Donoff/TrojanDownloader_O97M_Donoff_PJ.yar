
rule TrojanDownloader_O97M_Donoff_PJ{
	meta:
		description = "TrojanDownloader:O97M/Donoff.PJ,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 41 74 74 61 63 68 65 64 54 65 6d 70 6c 61 74 65 2e 50 61 74 68 20 26 20 22 5c 31 32 33 34 35 22 20 26 20 22 2e 64 6f 74 61 3a 6f 66 } //1 = ActiveDocument.AttachedTemplate.Path & "\12345" & ".dota:of
		$a_00_1 = {3d 20 4d 69 64 28 22 54 68 65 20 78 6f 73 68 65 6c 6c 3f 22 2c 20 37 2c 20 35 29 } //1 = Mid("The xoshell?", 7, 5)
		$a_00_2 = {3d 20 4d 69 64 28 22 41 72 65 20 44 65 73 63 72 69 70 74 3f 22 2c 20 37 2c 20 36 29 } //1 = Mid("Are Descript?", 7, 6)
		$a_00_3 = {50 75 74 20 23 53 49 4d 6f 6c 2c 20 2c 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2e 54 65 78 74 } //1 Put #SIMol, , ActiveDocument.Content.Text
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}