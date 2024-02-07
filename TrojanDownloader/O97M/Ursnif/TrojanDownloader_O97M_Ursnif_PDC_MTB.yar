
rule TrojanDownloader_O97M_Ursnif_PDC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.PDC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 6f 28 28 72 65 70 6c 61 63 65 28 72 74 72 69 6d 28 68 29 2c 22 22 2c 22 61 22 29 29 29 2c } //01 00  mo((replace(rtrim(h),"","a"))),
		$a_01_1 = {2c 64 65 73 74 69 6e 61 74 69 6f 6e 3a 3d 61 63 74 69 76 65 73 68 65 65 74 2e 72 61 6e 67 65 28 22 24 61 24 32 22 29 29 2e } //01 00  ,destination:=activesheet.range("$a$2")).
		$a_01_2 = {3d 68 75 62 62 26 22 22 26 70 61 72 65 67 67 69 61 74 6f 26 22 2c 23 31 2f 71 22 73 68 65 6c 6c 70 72 65 73 69 65 64 65 72 65 65 6e 64 66 75 6e 63 74 69 6f 6e 66 75 6e 63 74 69 6f 6e 68 65 72 6d 75 28 29 } //01 00  =hubb&""&pareggiato&",#1/q"shellpresiedereendfunctionfunctionhermu()
		$a_01_3 = {3d 73 61 6e 67 75 69 6e 61 6e 74 69 28 6c 65 66 74 28 65 6e 76 69 72 6f 6e 28 61 70 70 34 34 28 22 } //01 00  =sanguinanti(left(environ(app44("
		$a_01_4 = {64 65 65 65 3d 64 65 65 65 2b 72 72 6e 65 78 74 61 70 70 34 34 3d 64 65 65 65 65 6e 64 66 75 6e 63 74 69 6f 6e } //00 00  deee=deee+rrnextapp44=deeeendfunction
	condition:
		any of ($a_*)
 
}