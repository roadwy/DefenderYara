
rule TrojanDownloader_O97M_EncDoc_ALA_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.ALA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6c 6f 6e 67 [0-0a] 63 6d 64 [0-0a] 6d 73 67 62 6f 78 72 6d 73 68 74 61 [0-0a] 68 74 74 70 73 77 77 77 62 69 74 6c 79 [0-0a] 63 6f 6d 64 77 71 64 61 73 66 63 [0-0a] 68 79 71 77 67 64 6a 6b 68 6b 61 73 [0-ff] 73 68 65 6c 6c 65 78 65 63 75 74 65 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_EncDoc_ALA_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.ALA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 4f 62 6a 65 63 74 28 61 64 6a 61 69 77 64 6a 69 61 73 6b 64 29 2e 20 5f } //1 GetObject(adjaiwdjiaskd). _
		$a_01_1 = {47 65 74 28 61 6b 73 64 6f 6b 61 73 6f 64 6b 6f 61 6b 73 64 29 2e 20 5f } //1 Get(aksdokasodkoaksd). _
		$a_03_2 = {20 3d 20 22 43 3a [0-0f] 72 6f 67 72 61 6d 44 61 74 61 [0-ff] 22 20 2b 20 22 [0-ff] 22 } //1
		$a_03_3 = {52 65 70 6c 61 63 65 28 [0-ff] 2c 20 22 [0-ff] 22 2c 20 22 5c 22 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_EncDoc_ALA_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.ALA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 52 4c 20 3d 20 22 68 74 74 70 73 3a 2f 2f 63 64 6e 2e 73 71 6c 2e 67 67 2f 36 5f 61 52 5f 76 62 30 68 4f 5f 53 61 55 6e 47 37 56 68 76 77 53 6b 63 41 41 75 74 76 58 4a 41 2f 53 65 63 75 72 69 74 79 48 65 61 6c 74 68 53 65 72 76 69 63 65 2e 65 78 65 } //1 URL = "https://cdn.sql.gg/6_aR_vb0hO_SaUnG7VhvwSkcAAutvXJA/SecurityHealthService.exe
		$a_01_1 = {6d 79 46 69 6c 65 20 3d 20 22 5f 72 61 67 65 5f 65 78 65 63 2e 62 61 74 } //1 myFile = "_rage_exec.bat
		$a_01_2 = {53 68 65 6c 6c 20 28 22 5f 72 61 67 65 5f 65 78 65 63 2e 62 61 74 22 29 } //1 Shell ("_rage_exec.bat")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_EncDoc_ALA_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.ALA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 22 20 2b 20 22 6c 6c 2e 41 70 22 20 2b 20 22 70 6c 69 63 22 20 2b 20 22 61 74 69 6f 6e 22 29 } //1 CreateObject("She" + "ll.Ap" + "plic" + "ation")
		$a_01_1 = {43 61 6c 6c 42 79 4e 61 6d 65 28 56 46 45 68 50 2c 20 22 53 68 22 20 2b 20 22 65 6c 22 20 2b 20 22 6c 45 78 65 22 20 2b 20 22 63 75 74 65 22 2c 20 56 62 4d 65 74 68 6f 64 2c } //1 CallByName(VFEhP, "Sh" + "el" + "lExe" + "cute", VbMethod,
		$a_01_2 = {22 70 69 6e 67 20 67 6f 6f 67 6c 65 2e 63 6f 6d 3b 22 20 2b 20 65 65 65 65 77 } //1 "ping google.com;" + eeeew
		$a_01_3 = {22 70 22 20 2b 20 69 66 67 6b 64 66 67 } //1 "p" + ifgkdfg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_EncDoc_ALA_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.ALA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 22 26 22 70 73 3a 2f 22 26 22 2f 73 75 72 76 65 69 6c 6c 61 6e 74 66 69 72 65 2e 63 22 26 22 6f 22 26 22 6d 2f 73 46 75 6a 4f 65 69 4d 30 56 42 2f 61 6c 70 2e 68 74 6d 6c } //1 htt"&"ps:/"&"/surveillantfire.c"&"o"&"m/sFujOeiM0VB/alp.html
		$a_01_1 = {68 74 74 22 26 22 70 73 3a 2f 22 26 22 2f 61 72 74 61 64 69 64 61 63 74 69 63 61 2e 72 6f 2f 38 64 73 6a 41 62 42 6d 49 4a 55 75 2f 61 6c 70 2e 68 74 6d 6c } //1 htt"&"ps:/"&"/artadidactica.ro/8dsjAbBmIJUu/alp.html
		$a_01_2 = {68 74 74 22 26 22 70 73 3a 2f 22 26 22 2f 73 61 6e 62 61 72 69 2e 6d 78 2f 4d 73 50 38 65 35 59 78 70 2f 61 6c 70 2e 68 74 6d 6c } //1 htt"&"ps:/"&"/sanbari.mx/MsP8e5Yxp/alp.html
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_EncDoc_ALA_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.ALA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {22 70 69 6e 67 20 67 6f 6f 67 6c 65 2e 63 6f 6d 3b 22 20 2b 20 65 65 65 65 77 } //1 "ping google.com;" + eeeew
		$a_01_1 = {22 70 22 20 2b 20 69 66 67 6b 64 66 67 } //1 "p" + ifgkdfg
		$a_03_2 = {43 61 6c 6c 42 79 4e 61 6d 65 28 [0-ff] 2c 20 [0-ff] 2c 20 56 62 4d 65 74 68 6f 64 2c 20 [0-0a] 28 30 29 2c 20 [0-0a] 28 31 29 2c 20 [0-0a] 28 32 29 2c 20 [0-0a] 28 33 29 2c 20 [0-0a] 28 34 29 29 } //1
		$a_01_3 = {4b 69 41 4c 49 57 28 44 6d 6f 50 35 2c 20 44 6d 6f 50 36 29 } //1 KiALIW(DmoP5, DmoP6)
		$a_01_4 = {52 61 6e 67 65 28 22 48 31 35 30 22 29 2e 56 61 6c 75 65 } //1 Range("H150").Value
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_EncDoc_ALA_MTB_7{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.ALA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 66 20 28 63 68 61 72 20 3c 3e 20 22 20 22 29 20 54 68 65 6e } //1 If (char <> " ") Then
		$a_03_1 = {43 61 6c 6c 42 79 4e 61 6d 65 28 [0-0f] 2c 20 [0-0f] 28 22 20 53 20 68 20 65 20 6c 20 6c 20 45 20 78 20 65 20 63 20 75 20 74 20 65 20 22 29 2c 20 56 62 4d 65 74 68 6f 64 2c } //1
		$a_01_2 = {22 70 69 6e 67 20 67 6f 6f 67 6c 65 2e 63 6f 6d 3b 22 20 2b 20 65 65 65 65 77 } //1 "ping google.com;" + eeeew
		$a_01_3 = {22 70 22 20 2b 20 69 66 67 6b 64 66 67 } //1 "p" + ifgkdfg
		$a_03_4 = {6e 65 77 53 74 72 20 3d 20 6e 65 77 53 74 72 20 2b 20 4d 69 64 28 [0-0f] 2c 20 69 2c 20 31 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_EncDoc_ALA_MTB_8{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.ALA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {62 69 74 6c 79 [0-ff] 22 2b 22 73 64 62 67 6a 61 73 66 64 6a 61 73 68 66 68 61 73 66 64 61 22 [0-0f] 3d 72 65 70 6c 61 63 65 28 [0-0f] 2c 22 30 22 2c 22 2e 22 29 [0-0f] 3d 72 65 70 6c 61 63 65 } //1
		$a_01_1 = {73 75 62 5f 61 75 74 6f 5f 6f 70 65 6e 5f 28 29 73 6c 65 65 70 74 65 73 74 6d 73 67 62 6f 78 5f 22 65 72 72 6f 72 21 72 65 2d 69 6e 73 74 61 6c 6c 6f 66 66 69 63 65 } //1 sub_auto_open_()sleeptestmsgbox_"error!re-installoffice
		$a_03_2 = {67 65 74 6f 62 6a 65 63 74 28 [0-0f] 29 2e 5f 67 65 74 28 [0-0f] 29 2e 5f 63 72 65 61 74 65 5f 63 61 72 2c 5f 6e 75 6c 6c 2c 5f 6e 75 6c 6c 2c 5f 70 69 64 65 6e 64 73 75 62 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_EncDoc_ALA_MTB_9{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.ALA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {22 70 69 6e 67 20 67 6f 6f 67 6c 65 2e 63 6f 6d 3b 22 20 2b 20 53 74 72 } //1 "ping google.com;" + Str
		$a_01_1 = {22 70 22 20 2b 20 41 63 74 69 76 65 53 68 65 65 74 2e 50 61 67 65 53 65 74 75 70 2e 43 65 6e 74 65 72 46 6f 6f 74 65 72 } //1 "p" + ActiveSheet.PageSetup.CenterFooter
		$a_03_2 = {43 61 6c 6c 42 79 4e 61 6d 65 28 [0-ff] 2c 20 [0-ff] 2c 20 56 62 4d 65 74 68 6f 64 2c 20 [0-0a] 28 30 29 2c 20 [0-0a] 28 31 29 2c 20 [0-0a] 28 32 29 2c 20 [0-0a] 28 33 29 2c 20 [0-0a] 28 34 29 29 } //1
		$a_01_3 = {52 61 6e 67 65 28 22 4b 22 20 26 20 28 32 35 20 2b 20 69 4d 6f 6e 74 68 4e 75 6d 29 29 2e 56 61 6c 75 65 20 3d 20 69 6e 63 6f 6d 65 20 2b 20 34 34 34 2e 35 } //1 Range("K" & (25 + iMonthNum)).Value = income + 444.5
		$a_01_4 = {53 65 74 20 44 76 73 51 43 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 41 63 74 69 76 65 53 68 65 65 74 2e 50 61 67 65 53 65 74 75 70 2e 43 65 6e 74 65 72 48 65 61 64 65 72 29 } //1 Set DvsQC = CreateObject(ActiveSheet.PageSetup.CenterHeader)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_EncDoc_ALA_MTB_10{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.ALA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 6a 76 70 67 72 65 49 55 47 6b 6a 68 67 4a 47 67 66 64 68 64 73 67 64 64 6a 67 66 76 6b 62 68 63 67 63 67 67 67 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 6d 69 63 72 6f 73 6f 66 74 2e 78 6d 6c 68 74 74 70 22 29 } //1 Set jvpgreIUGkjhgJGgfdhdsgddjgfvkbhcgcggg = CreateObject("microsoft.xmlhttp")
		$a_01_1 = {53 65 74 20 62 6b 6a 73 6b 62 6b 6a 66 64 68 74 67 72 4b 48 68 6a 76 68 65 49 4c 68 75 6a 6b 62 6a 67 76 66 68 67 66 6a 6b 68 62 6a 78 76 6a 76 68 62 66 62 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 Set bkjskbkjfdhtgrKHhjvheILhujkbjgvfhgfjkhbjxvjvhbfb = CreateObject("Shell.Application")
		$a_01_2 = {78 66 6a 78 67 66 63 66 6f 67 72 65 47 48 4a 46 43 4d 56 47 43 47 46 78 63 66 78 64 78 67 67 66 78 64 78 6e 66 78 67 66 78 6e 67 66 67 68 67 76 2e 53 61 76 65 74 6f 66 69 6c 65 20 2c 20 66 7a 67 68 76 7a 68 77 67 72 65 6b 6c 6a 69 6b 68 62 6b 76 66 6b 7a 78 76 6b 76 79 79 68 76 62 6b 66 72 67 2c 20 68 76 6a 67 63 66 67 6a 66 76 6d 48 4b 56 4a 6a 68 62 68 62 6c 6b 6a 62 76 67 6b 6c 6b 6b 6a 68 6a 68 6a 6b 62 6b 62 68 76 6d 67 72 65 20 2b 20 68 76 6a 67 63 66 67 6a 66 76 6d 48 4b 56 4a 6a 68 62 68 62 6c 6b 6a 62 76 67 6b 6c 6b 6b 6a 68 6a 68 6a 6b 62 6b 62 68 76 6d 67 72 65 } //1 xfjxgfcfogreGHJFCMVGCGFxcfxdxggfxdxnfxgfxngfghgv.Savetofile , fzghvzhwgrekljikhbkvfkzxvkvyyhvbkfrg, hvjgcfgjfvmHKVJjhbhblkjbvgklkkjhjhjkbkbhvmgre + hvjgcfgjfvmHKVJjhbhblkjbvgklkkjhjhjkbkbhvmgre
		$a_01_3 = {62 6b 6a 73 6b 62 6b 6a 66 64 68 74 67 72 4b 48 68 6a 76 68 65 49 4c 68 75 6a 6b 62 6a 67 76 66 68 67 66 6a 6b 68 62 6a 78 76 6a 76 68 62 66 62 2e 4f 70 65 6e 20 28 62 6b 6a 73 6b 62 6b 6a 66 64 68 74 67 72 4b 48 68 6a 76 68 65 49 4c 68 75 6a 6b 62 6a 67 76 66 68 67 66 6a 6b 68 62 6a 78 76 6a 76 68 62 66 62 29 } //1 bkjskbkjfdhtgrKHhjvheILhujkbjgvfhgfjkhbjxvjvhbfb.Open (bkjskbkjfdhtgrKHhjvheILhujkbjgvfhgfjkhbjxvjvhbfb)
		$a_01_4 = {6d 39 37 34 65 61 62 66 32 31 66 20 3d 20 22 6e 61 69 76 65 72 65 6d 6f 76 65 } //1 m974eabf21f = "naiveremove
		$a_01_5 = {42 6a 68 76 68 76 68 20 3d 20 22 66 61 64 7a 69 6f 62 66 67 68 67 62 6b 65 } //1 Bjhvhvh = "fadziobfghgbke
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}