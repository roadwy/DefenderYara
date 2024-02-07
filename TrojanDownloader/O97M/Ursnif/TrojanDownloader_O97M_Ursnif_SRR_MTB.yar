
rule TrojanDownloader_O97M_Ursnif_SRR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.SRR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 45 6e 76 69 72 6f 6e 24 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 26 20 22 5c 44 6f 63 75 6d 65 6e 74 73 22 20 26 20 5f } //01 00  = Environ$("USERPROFILE") & "\Documents" & _
		$a_01_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 4d 53 58 4d 4c 32 2e 58 4d 4c 48 54 54 50 22 29 } //01 00  = CreateObject("MSXML2.XMLHTTP")
		$a_01_2 = {64 65 66 6f 72 6d 61 74 6f 2e 4f 70 65 6e 20 22 67 65 74 22 2c 20 73 71 75 69 6c 69 62 72 61 74 69 2c 20 46 61 6c 73 65 } //01 00  deformato.Open "get", squilibrati, False
		$a_01_3 = {64 65 66 6f 72 6d 61 74 6f 2e 73 65 74 52 65 71 75 65 73 74 48 65 61 64 65 72 20 22 65 74 61 67 22 2c 20 22 66 65 74 63 68 22 } //01 00  deformato.setRequestHeader "etag", "fetch"
		$a_01_4 = {4d 73 67 42 6f 78 20 28 4c 65 6e 28 72 65 73 69 73 74 65 72 6d 69 28 28 69 6e 74 72 65 63 63 69 61 74 6f 28 22 68 33 33 74 31 74 70 33 30 73 3a 31 2f 2f 32 35 6c 69 31 35 6a 6f 73 31 61 2e 63 38 30 6f 34 6d 22 29 29 29 29 20 2d 20 34 30 34 29 } //00 00  MsgBox (Len(resistermi((intrecciato("h33t1tp30s:1//25li15jos1a.c80o4m")))) - 404)
	condition:
		any of ($a_*)
 
}