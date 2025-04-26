
rule TrojanDownloader_O97M_EncDoc_SPP_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SPP!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {44 65 62 75 67 2e 50 72 69 6e 74 20 64 65 6c 69 7a 69 6f 73 61 6d 65 6e 74 65 28 64 65 62 75 67 47 28 22 32 68 74 34 30 74 31 70 31 31 73 34 3a 36 2f 31 32 2f 62 35 62 70 30 6c 69 37 38 6e 65 33 2e 63 34 6f 30 6d 34 22 29 29 } //1 Debug.Print deliziosamente(debugG("2ht40t1p11s4:6/12/b5bp0li78ne3.c4o0m4"))
		$a_01_1 = {6f 58 48 54 54 50 2e 4f 70 65 6e 20 22 67 65 74 22 2c 20 73 69 75 2c 20 46 61 6c 73 65 } //1 oXHTTP.Open "get", siu, False
		$a_01_2 = {6f 58 48 54 54 50 2e 73 65 74 52 65 71 75 65 73 74 48 65 61 64 65 72 20 22 65 74 61 67 22 2c 20 22 66 65 74 63 68 22 } //1 oXHTTP.setRequestHeader "etag", "fetch"
		$a_01_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 41 44 4f 44 42 2e 53 74 72 65 61 6d 22 29 } //1 = CreateObject("ADODB.Stream")
		$a_01_4 = {64 65 62 75 67 47 28 22 31 35 72 32 34 75 35 6e 35 64 33 6c 31 6c 31 38 22 29 20 26 20 6f 4c } //1 debugG("15r24u5n5d3l1l18") & oL
		$a_01_5 = {45 6e 76 69 72 6f 6e 24 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 20 26 20 22 5c 44 6f 63 75 6d 65 6e 74 73 22 20 26 20 5f } //1 Environ$("USERPROFILE") & "\Documents" & _
		$a_01_6 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 50 61 74 68 53 65 70 61 72 61 74 6f 72 20 26 20 5f } //1 Application.PathSeparator & _
		$a_01_7 = {67 6a 20 26 20 22 2e 72 61 77 22 } //1 gj & ".raw"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}