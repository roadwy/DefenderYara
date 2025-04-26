
rule TrojanDownloader_O97M_Hancitor_EOAC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Hancitor.EOAC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 61 74 74 69 73 6f 6e 20 3d 20 22 5c 69 65 72 2e 64 22 } //1 pattison = "\ier.d"
		$a_01_1 = {43 61 6c 6c 20 53 65 61 72 63 68 28 4d 79 46 53 4f 2e 47 65 74 46 6f 6c 64 65 72 28 61 73 64 61 29 2c 20 68 64 76 29 } //1 Call Search(MyFSO.GetFolder(asda), hdv)
		$a_01_2 = {62 62 62 62 20 26 20 63 76 7a 7a 2c 20 76 63 62 63 20 26 20 70 61 74 74 69 73 6f 6e 20 26 20 22 6c 6c 22 } //1 bbbb & cvzz, vcbc & pattison & "ll"
		$a_01_3 = {62 62 62 62 20 3d 20 62 62 62 62 20 26 20 22 75 22 20 26 20 64 66 67 64 67 64 67 } //1 bbbb = bbbb & "u" & dfgdgdg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}