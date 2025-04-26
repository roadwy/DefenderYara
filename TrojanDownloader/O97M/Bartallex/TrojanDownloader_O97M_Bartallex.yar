
rule TrojanDownloader_O97M_Bartallex{
	meta:
		description = "TrojanDownloader:O97M/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2f 37 72 76 6d 6e 62 [0-28] 2f 61 66 2f 37 72 76 6d 6e 62 [0-28] 2f 61 66 2f 37 72 76 6d 6e 62 [0-28] 2f 37 72 76 6d 6e 62 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Bartallex_2{
	meta:
		description = "TrojanDownloader:O97M/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {75 67 67 63 3a 2f 2f 6e 79 68 70 6e 65 71 62 61 6e 2e 70 62 7a 2f 77 66 2f 6f 76 61 2e 72 6b 72 } //1 uggc://nyhpneqban.pbz/wf/ova.rkr
		$a_01_1 = {5c 71 66 55 55 55 2e 72 6b 72 } //1 \qfUUU.rkr
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Bartallex_3{
	meta:
		description = "TrojanDownloader:O97M/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 50 6c 4b 74 52 65 62 47 66 20 3d 20 6f 47 64 79 65 4a 64 68 73 64 64 2e 54 65 78 74 42 6f 78 34 20 2b 20 69 75 79 68 67 64 66 73 64 66 20 2b 20 68 79 79 75 65 6a 6b 6a 73 20 2b 20 79 79 65 69 64 73 61 64 66 20 2b 20 79 65 75 69 6a 6a 66 66 73 61 } //1 oPlKtRebGf = oGdyeJdhsdd.TextBox4 + iuyhgdfsdf + hyyuejkjs + yyeidsadf + yeuijjffsa
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Bartallex_4{
	meta:
		description = "TrojanDownloader:O97M/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {55 47 39 33 5a 58 4a 54 61 47 56 73 62 43 41 74 52 58 68 6c 59 33 56 30 61 57 39 75 55 47 39 73 61 57 4e 35 49 47 4a 35 63 47 46 7a 63 79 41 74 62 6d 39 77 63 6d 39 6d 61 57 78 6c 49 43 31 33 61 57 35 6b 62 33 64 7a 64 48 6c 73 5a 53 42 6f 61 57 52 6b 5a 57 34 67 } //1 UG93ZXJTaGVsbCAtRXhlY3V0aW9uUG9saWN5IGJ5cGFzcyAtbm9wcm9maWxlIC13aW5kb3dzdHlsZSBoaWRkZW4g
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Bartallex_5{
	meta:
		description = "TrojanDownloader:O97M/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 6f 72 20 69 20 3d 20 4c 42 6f 75 6e 64 28 42 79 56 61 6c 76 44 65 66 61 75 6c 74 29 20 54 6f 20 55 42 6f 75 6e 64 28 42 79 56 61 6c 76 44 65 66 61 75 6c 74 29 } //2 For i = LBound(ByValvDefault) To UBound(ByValvDefault)
		$a_01_1 = {4f 62 6a 49 6e 64 65 78 20 3d 20 4f 62 6a 49 6e 64 65 78 20 26 20 43 68 72 28 } //2 ObjIndex = ObjIndex & Chr(
		$a_01_2 = {57 53 63 72 69 70 74 2e 53 68 65 6c 6c } //1 WScript.Shell
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Bartallex_6{
	meta:
		description = "TrojanDownloader:O97M/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 48 54 20 3d 20 22 22 20 26 20 22 68 74 22 20 26 20 22 74 22 20 26 20 22 70 3a 2f 2f 22 20 26 20 22 22 } //1 PHT = "" & "ht" & "t" & "p://" & ""
		$a_01_1 = {53 50 49 43 20 3d 20 22 22 20 26 20 22 73 22 20 26 20 22 61 76 22 20 26 20 22 65 70 69 22 20 2b 20 22 63 2e 73 75 22 20 2b 20 22 2f 22 } //1 SPIC = "" & "s" & "av" & "epi" + "c.su" + "/"
		$a_01_2 = {4c 4e 53 53 20 3d 20 22 6c 6e 73 2e 74 78 74 22 } //1 LNSS = "lns.txt"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Bartallex_7{
	meta:
		description = "TrojanDownloader:O97M/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6f 62 6a 50 72 6f 63 65 73 73 2e 43 72 65 61 74 65 20 22 70 6f 77 65 72 22 20 26 20 22 73 68 65 6c 6c 22 20 26 20 22 2e 65 78 65 20 2d 45 78 65 63 75 74 69 6f 6e 50 6f 6c 69 63 79 20 42 79 70 61 73 73 20 2d 57 69 6e 64 6f 77 53 74 79 6c 65 20 48 69 64 64 65 6e 20 2d 6e 6f 70 72 6f 66 69 6c 65 20 2d 6e 6f 65 78 69 74 } //1 objProcess.Create "power" & "shell" & ".exe -ExecutionPolicy Bypass -WindowStyle Hidden -noprofile -noexit
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Bartallex_8{
	meta:
		description = "TrojanDownloader:O97M/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 53 66 4f 30 61 33 75 61 30 71 65 42 2c 20 30 } //1 Shell SfO0a3ua0qeB, 0
		$a_01_1 = {53 66 4f 30 61 33 75 61 30 71 65 42 20 3d 20 53 66 4f 30 61 33 75 61 30 71 65 42 20 26 20 22 32 33 39 2c 32 34 30 2c 32 30 32 2c 32 32 36 2c 32 33 37 2c 32 30 32 2c 32 30 2c 32 30 2c 31 31 38 2c 36 31 2c 38 39 2c 36 34 2c 38 2c 31 32 33 2c 36 35 2c 35 37 2c 36 32 } //1 SfO0a3ua0qeB = SfO0a3ua0qeB & "239,240,202,226,237,202,20,20,118,61,89,64,8,123,65,57,62
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Bartallex_9{
	meta:
		description = "TrojanDownloader:O97M/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {66 73 70 72 65 73 65 6e 74 61 74 69 6f 6e 70 72 6f 64 75 63 74 73 2e 63 6f 6d 2f } //1 fspresentationproducts.com/
		$a_01_1 = {22 63 68 61 6d 65 6c 65 6f 6e 70 61 69 6e 74 77 6f 72 6b 73 2e 63 6f 6d 2f 77 22 20 2b 20 22 70 2d 63 6f 6e 22 20 2b 20 22 74 65 6e 74 2f 70 6c 22 20 2b 20 22 75 67 69 6e 73 2f 77 22 20 2b 20 22 70 2d 6a 71 75 22 20 2b 20 22 65 72 79 2d 6c 69 67 22 20 2b 20 22 68 74 62 6f 78 2f 73 74 79 22 20 2b 20 22 6c 65 73 2f 69 6d 61 67 22 20 2b 20 22 65 73 2f 68 65 5f 49 4c 2f 22 } //1 "chameleonpaintworks.com/w" + "p-con" + "tent/pl" + "ugins/w" + "p-jqu" + "ery-lig" + "htbox/sty" + "les/imag" + "es/he_IL/"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Bartallex_10{
	meta:
		description = "TrojanDownloader:O97M/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {22 77 77 77 2e 69 6e 22 20 2b 20 22 63 61 6c 74 61 6d 69 6e 74 65 2e 69 6e 22 20 2b 20 22 66 6f 2f 77 22 20 2b 20 22 70 2d 63 6f 6e 74 65 6e 74 2f 75 70 6c 22 20 2b 20 22 6f 61 64 73 2f 32 30 31 22 20 2b 20 22 35 2f 30 22 20 2b 20 22 36 2f 22 } //1 "www.in" + "caltaminte.in" + "fo/w" + "p-content/upl" + "oads/201" + "5/0" + "6/"
		$a_01_1 = {22 77 77 77 2e 69 73 63 6d 6f 22 20 2b 20 22 6e 74 65 67 72 61 6e 61 72 6f 2e 69 74 2f 77 22 20 2b 20 22 70 2d 63 6f 6e 74 65 6e 74 2f 75 70 6c 22 20 2b 20 22 6f 61 64 73 2f 32 30 31 22 20 2b 20 22 35 2f 30 22 20 2b 20 22 36 2f 22 } //1 "www.iscmo" + "ntegranaro.it/w" + "p-content/upl" + "oads/201" + "5/0" + "6/"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Bartallex_11{
	meta:
		description = "TrojanDownloader:O97M/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 6f 72 20 69 20 3d 20 4c 42 6f 75 6e 64 28 42 79 56 61 6c 76 44 65 66 61 75 6c 74 29 20 54 6f 20 55 42 6f 75 6e 64 28 42 79 56 61 6c 76 44 65 66 61 75 6c 74 29 } //1 For i = LBound(ByValvDefault) To UBound(ByValvDefault)
		$a_01_1 = {50 72 6f 63 65 73 73 4b 69 6c 6c 4f 72 64 65 72 20 3d 20 50 72 6f 63 65 73 73 4b 69 6c 6c 4f 72 64 65 72 20 26 20 43 68 72 28 42 79 56 61 6c 76 44 65 66 61 75 6c 74 28 69 29 20 2d 20 33 33 20 2a 20 4e 6f 74 68 69 6e 67 4f 72 4e 6f 64 65 4e 61 6d 65 20 2d 20 35 35 34 34 20 2d 20 37 37 38 20 2d 20 33 35 29 } //1 ProcessKillOrder = ProcessKillOrder & Chr(ByValvDefault(i) - 33 * NothingOrNodeName - 5544 - 778 - 35)
		$a_01_2 = {57 53 41 47 65 74 53 65 6c 65 63 74 45 76 65 6e 74 32 20 3d 20 50 72 6f 63 65 73 73 4b 69 6c 6c 4f 72 64 65 72 } //1 WSAGetSelectEvent2 = ProcessKillOrder
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Bartallex_12{
	meta:
		description = "TrojanDownloader:O97M/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 68 72 24 28 34 37 29 20 26 20 43 68 72 24 28 39 39 29 20 2b 20 43 68 72 24 28 39 37 29 20 26 20 43 68 72 24 28 31 31 32 29 20 26 20 43 68 72 24 28 31 31 36 29 20 2b 20 43 68 72 24 28 39 37 29 20 26 20 43 68 72 24 28 31 30 35 29 } //1 Chr$(47) & Chr$(99) + Chr$(97) & Chr$(112) & Chr$(116) + Chr$(97) & Chr$(105)
		$a_01_1 = {43 68 72 24 28 31 31 30 29 20 26 20 43 68 72 24 28 34 37 29 20 2b 20 43 68 72 24 28 39 38 29 20 26 20 43 68 72 24 28 31 30 38 29 20 2b 20 43 68 72 24 28 39 37 29 } //1 Chr$(110) & Chr$(47) + Chr$(98) & Chr$(108) + Chr$(97)
		$a_01_2 = {43 68 72 24 28 39 39 29 20 26 20 43 68 72 24 28 31 30 37 29 20 26 20 43 68 72 24 28 34 36 29 20 26 20 43 68 72 24 28 31 31 32 29 20 26 20 43 68 72 24 28 31 30 34 29 20 2b 20 43 68 72 24 28 31 31 32 29 } //1 Chr$(99) & Chr$(107) & Chr$(46) & Chr$(112) & Chr$(104) + Chr$(112)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Bartallex_13{
	meta:
		description = "TrojanDownloader:O97M/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {50 75 62 6c 69 63 20 53 75 62 20 [0-0f] 28 29 90 0c 03 00 [0-1f] 20 3d 20 53 70 6c 69 74 28 22 90 10 04 00 7c 90 10 04 00 7c 90 10 04 00 7c 90 10 04 00 7c 90 10 04 00 7c 90 10 04 00 } //1
		$a_03_1 = {46 6f 72 20 [0-0f] 20 3d 20 4c 42 6f 75 6e 64 28 [0-0f] 29 20 54 6f 20 55 42 6f 75 6e 64 28 90 1b 01 29 [0-1f] 20 3d 20 [0-1f] 20 26 20 43 68 72 28 43 49 6e 74 28 90 1b 01 28 [0-1f] 29 29 20 2d 20 90 10 04 00 29 } //1
		$a_03_2 = {5f 31 2e 4f 70 65 6e 20 (68 75 62 61 62 75 62 61|4b 72 69 70 6f 74 61) 28 90 10 03 00 29 2c 20 [0-1f] 5f 31 2c 20 46 61 6c 73 65 } //1
		$a_03_3 = {41 73 20 42 6f 6f 6c 65 61 6e [0-20] 5f 90 0f 01 00 20 3d 20 53 70 6c 69 74 28 22 90 10 04 00 2c 90 10 04 00 2c 90 10 04 00 2c 90 10 04 00 2c 90 10 04 00 2c 90 10 04 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Bartallex_14{
	meta:
		description = "TrojanDownloader:O97M/Bartallex,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {22 6d 69 73 74 61 74 75 61 6a 65 73 2e 63 6f 6d 2e 65 73 2f 77 22 20 2b 20 22 70 2d 63 6f 22 20 2b 20 22 6e 74 65 6e 74 2f 70 6c 75 22 20 2b 20 22 67 69 6e 73 2f 77 6f 72 22 20 2b 20 22 64 70 22 20 2b 20 22 72 65 73 73 2d 73 65 6f 2f 76 22 20 2b 20 22 65 6e 64 6f 72 2f 79 6f 22 20 2b 20 22 61 73 74 2f 6c 69 63 22 20 2b 20 22 65 6e 73 65 2d 6d 61 6e 22 20 2b 20 22 61 67 65 72 2f 73 61 22 20 2b 20 22 6d 70 6c 65 73 2f 22 } //1 "mistatuajes.com.es/w" + "p-co" + "ntent/plu" + "gins/wor" + "dp" + "ress-seo/v" + "endor/yo" + "ast/lic" + "ense-man" + "ager/sa" + "mples/"
		$a_01_1 = {22 6d 69 73 66 72 75 74 61 6c 65 73 2e 63 6f 6d 2e 65 73 2f 77 22 20 2b 20 22 70 2d 63 6f 22 20 2b 20 22 6e 74 65 6e 22 20 2b 20 22 74 2f 70 22 20 2b 20 22 6c 75 67 69 6e 22 20 2b 20 22 73 2f 6e 69 6e 22 20 2b 20 22 6a 61 2d 70 6f 70 22 20 2b 20 22 75 70 73 2f 61 64 6d 22 20 2b 20 22 69 6e 2f 63 73 22 20 2b 20 22 73 2f 6a 71 75 22 20 2b 20 22 65 72 79 2d 75 69 2d 61 72 69 22 20 2b 20 22 73 74 6f 2f 69 6d 61 22 20 2b 20 22 67 65 73 2f 22 } //1 "misfrutales.com.es/w" + "p-co" + "nten" + "t/p" + "lugin" + "s/nin" + "ja-pop" + "ups/adm" + "in/cs" + "s/jqu" + "ery-ui-ari" + "sto/ima" + "ges/"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}