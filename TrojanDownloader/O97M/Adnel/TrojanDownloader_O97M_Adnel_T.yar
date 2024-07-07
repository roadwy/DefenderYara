
rule TrojanDownloader_O97M_Adnel_T{
	meta:
		description = "TrojanDownloader:O97M/Adnel.T,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {2c 20 53 74 72 52 65 76 65 72 73 65 28 22 22 22 20 72 69 64 6b 6d 20 63 2f 20 64 6d 63 22 29 20 26 } //1 , StrReverse(""" ridkm c/ dmc") &
		$a_00_1 = {26 20 52 69 67 68 74 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 4e 61 6d 65 2c 20 31 29 20 26 20 22 72 69 70 74 2e 53 68 22 20 26 20 53 74 72 52 65 76 65 72 73 65 28 22 6c 6c 65 22 29 29 } //1 & Right(ActiveDocument.Name, 1) & "ript.Sh" & StrReverse("lle"))
		$a_00_2 = {26 20 53 74 72 52 65 76 65 72 73 65 28 22 74 69 78 65 20 26 20 22 22 22 29 2c 20 30 2c 20 54 72 75 65 } //1 & StrReverse("tixe & """), 0, True
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}