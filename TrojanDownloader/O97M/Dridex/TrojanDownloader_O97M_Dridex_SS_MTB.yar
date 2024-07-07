
rule TrojanDownloader_O97M_Dridex_SS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Dridex.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 52 65 70 6c 61 63 65 28 22 4d 53 58 4d 4c 4b 73 71 25 70 2c 32 2e 58 4d 4c 48 54 54 50 22 2c 20 22 4b 73 71 25 70 2c 22 2c 20 22 22 29 } //1 = Replace("MSXMLKsq%p,2.XMLHTTP", "Ksq%p,", "")
		$a_01_1 = {3d 20 52 65 70 6c 61 63 65 28 22 72 75 6e 67 4a 49 70 67 5f 58 64 67 4a 49 70 67 5f 58 6c 6c 33 32 2e 65 78 67 } //1 = Replace("rungJIpg_XdgJIpg_Xll32.exg
		$a_01_2 = {4d 73 67 20 3d 20 22 54 68 61 6e 6b 20 59 6f 75 21 } //1 Msg = "Thank You!
		$a_01_3 = {4d 73 67 42 6f 78 20 4d 73 67 2c 20 2c 20 22 4f 4b 22 2c 20 45 72 72 2e 48 65 6c 70 46 69 6c 65 2c 20 45 72 72 2e 48 65 6c 70 43 6f 6e 74 65 78 74 } //1 MsgBox Msg, , "OK", Err.HelpFile, Err.HelpContext
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Dridex_SS_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Dridex.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_03_0 = {57 69 74 68 20 47 65 74 4f 62 6a 65 63 74 28 90 02 0f 29 90 00 } //1
		$a_03_1 = {20 3d 20 53 70 6c 69 74 28 90 02 0f 2c 20 90 02 0e 2c 20 90 02 0f 29 90 00 } //1
		$a_03_2 = {3d 20 52 65 70 6c 61 63 65 28 90 02 0f 2c 20 90 02 0f 2c 20 90 02 0f 29 90 00 } //1
		$a_03_3 = {2e 43 72 65 61 74 65 20 90 02 17 2c 20 4e 75 6c 6c 2c 20 90 00 } //1
		$a_03_4 = {46 6f 72 20 90 02 0e 20 3d 20 30 20 54 6f 20 43 4c 6e 67 28 28 90 00 } //1
		$a_03_5 = {78 6c 44 69 61 6c 6f 90 02 2f 20 58 6f 72 20 90 00 } //1
		$a_01_6 = {3d 20 45 6e 76 69 72 6f 6e 28 } //1 = Environ(
		$a_01_7 = {29 29 29 29 20 2a 20 52 6e 64 20 2b 20 43 4c 6e 67 28 28 } //1 )))) * Rnd + CLng((
		$a_01_8 = {20 3d 20 48 65 78 28 43 4c 6e 67 28 28 43 4c 6e 67 28 28 } //1  = Hex(CLng((CLng((
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}
rule TrojanDownloader_O97M_Dridex_SS_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Dridex.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {2e 45 78 65 63 20 28 22 6d 73 68 74 61 20 22 20 26 20 43 68 72 28 33 34 29 20 26 20 45 6e 76 69 72 6f 6e 28 22 41 4c 4c 55 53 45 52 53 50 52 4f 46 49 4c 45 22 29 20 26 20 22 5c 71 44 69 61 6c 6f 67 47 61 6c 6c 65 72 79 53 63 61 74 74 65 72 2e 73 63 74 22 20 26 20 43 68 72 28 33 34 29 29 90 02 03 45 6e 64 20 57 69 74 68 90 00 } //1
		$a_01_1 = {71 41 78 69 73 20 3d 20 71 41 78 69 73 20 26 20 43 68 72 28 71 49 4d 45 4d 6f 64 65 41 6c 70 68 61 46 75 6c 6c 2e 56 61 6c 75 65 29 } //1 qAxis = qAxis & Chr(qIMEModeAlphaFull.Value)
		$a_01_2 = {57 69 74 68 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 73 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 With CreateObject("Wscript.Shell")
		$a_03_3 = {71 47 72 69 64 2e 57 72 69 74 65 20 28 71 41 78 69 73 29 90 02 03 71 47 72 69 64 2e 43 6c 6f 73 65 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Dridex_SS_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Dridex.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {75 20 3d 20 75 20 26 20 43 68 72 28 41 73 63 28 4d 69 64 28 6e 2c 20 58 2c 20 31 29 29 20 2b 20 6b 29 3a 20 4e 65 78 74 } //1 u = u & Chr(Asc(Mid(n, X, 1)) + k): Next
		$a_01_1 = {44 65 62 75 67 2e 50 72 69 6e 74 20 52 65 70 6c 61 63 65 28 45 2c 20 22 5b 22 2c 20 22 4a 22 29 } //1 Debug.Print Replace(E, "[", "J")
		$a_01_2 = {49 52 20 3d 20 53 70 6c 69 74 28 75 2c 20 22 3e 22 29 } //1 IR = Split(u, ">")
		$a_01_3 = {61 28 6a 25 20 2b 20 31 29 20 3d 20 58 25 } //1 a(j% + 1) = X%
		$a_01_4 = {72 73 20 3d 20 72 73 20 26 20 5b 4d 49 44 28 22 41 42 43 44 20 45 46 47 48 20 49 4a 4b 4c 20 4d 4e 4f 20 50 51 52 53 20 54 55 56 57 58 20 59 5a 61 62 63 20 64 65 66 67 68 69 20 6a 6b 6c 6d 6e 6f 20 70 71 72 73 74 75 20 76 77 78 79 7a 22 2c 52 41 4e 44 42 45 54 57 45 45 4e 28 31 2c 36 32 29 2c 31 29 5d } //1 rs = rs & [MID("ABCD EFGH IJKL MNO PQRS TUVWX YZabc defghi jklmno pqrstu vwxyz",RANDBETWEEN(1,62),1)]
		$a_01_5 = {69 6e 6e 20 3d 20 43 68 72 28 41 73 63 28 61 28 58 29 29 20 2d 20 31 29 } //1 inn = Chr(Asc(a(X)) - 1)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule TrojanDownloader_O97M_Dridex_SS_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Dridex.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 52 65 70 6c 61 63 65 28 22 41 40 2d 23 38 56 57 70 40 2d 23 38 56 57 70 44 61 74 61 22 2c 20 22 40 2d 23 38 56 57 22 2c 20 22 22 29 } //1 = Replace("A@-#8VWp@-#8VWpData", "@-#8VW", "")
		$a_01_1 = {3d 20 52 65 70 6c 61 63 65 28 22 4f 66 66 6c 35 54 52 38 4c 4c 69 35 54 52 38 4c 4c 6e 65 35 54 52 38 4c 4c 35 54 52 38 4c 4c 46 35 54 52 38 4c 4c 69 6c 65 73 53 74 61 72 35 54 52 38 4c 4c 74 22 2c 20 22 35 54 52 38 4c 4c 22 2c 20 22 22 29 } //1 = Replace("Offl5TR8LLi5TR8LLne5TR8LL5TR8LLF5TR8LLilesStar5TR8LLt", "5TR8LL", "")
		$a_01_2 = {3d 20 52 65 70 6c 61 63 65 28 22 57 73 63 72 69 70 33 21 34 46 49 74 33 21 34 46 49 2e 53 68 65 6c 6c 22 2c 20 22 33 21 34 46 49 22 2c 20 22 22 29 } //1 = Replace("Wscrip3!4FIt3!4FI.Shell", "3!4FI", "")
		$a_01_3 = {3d 20 52 65 70 6c 61 63 65 28 22 77 6d 69 63 20 70 72 6f 63 65 73 73 20 63 61 6c 6c 20 63 72 65 61 74 65 20 27 72 75 6e 24 33 26 70 52 2b 64 6c 6c 33 32 2e 65 78 65 20 22 2c 20 22 24 33 26 70 52 2b 22 2c 20 22 22 29 } //1 = Replace("wmic process call create 'run$3&pR+dll32.exe ", "$3&pR+", "")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Dridex_SS_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/Dridex.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 20 52 65 70 6c 61 63 65 28 22 5c 31 51 4d 3a 29 33 38 5a 51 4d 3a 29 33 38 5a 31 39 38 31 2e 51 4d 3a 29 33 38 5a 64 6c 6c 22 2c 20 22 51 4d 3a 29 33 38 5a 22 2c 20 22 22 29 } //1 = Replace("\1QM:)38ZQM:)38Z1981.QM:)38Zdll", "QM:)38Z", "")
		$a_01_1 = {3d 20 52 65 70 6c 61 63 65 28 22 7a 38 67 2a 42 37 37 41 7a 38 67 2a 42 37 37 70 7a 38 67 2a 42 37 37 70 44 61 74 61 22 2c 20 22 7a 38 67 2a 42 37 37 22 2c 20 22 22 29 } //1 = Replace("z8g*B77Az8g*B77pz8g*B77pData", "z8g*B77", "")
		$a_01_2 = {3d 20 52 65 70 6c 61 63 65 28 22 4f 66 20 24 65 4d 25 66 6c 69 6e 20 24 65 4d 25 65 46 20 24 65 4d 25 69 6c 20 24 65 4d 25 20 24 65 4d 25 65 20 24 65 4d 25 73 53 74 61 72 74 22 2c 20 22 20 24 65 4d 25 22 2c 20 22 22 29 } //1 = Replace("Of $eM%flin $eM%eF $eM%il $eM% $eM%e $eM%sStart", " $eM%", "")
		$a_01_3 = {4d 73 67 20 3d 20 22 54 68 61 6e 6b 20 59 6f 75 21 } //1 Msg = "Thank You!
		$a_01_4 = {4d 73 67 42 6f 78 20 4d 73 67 2c 20 2c 20 22 4f 4b 22 2c 20 45 72 72 2e 48 65 6c 70 46 69 6c 65 2c 20 45 72 72 2e 48 65 6c 70 43 6f 6e 74 65 78 74 } //1 MsgBox Msg, , "OK", Err.HelpFile, Err.HelpContext
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Dridex_SS_MTB_7{
	meta:
		description = "TrojanDownloader:O97M/Dridex.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 0a 00 00 "
		
	strings :
		$a_03_0 = {3d 20 52 65 70 6c 61 63 65 28 22 90 02 2f 2e 64 6c 6c 22 2c 20 22 90 02 0a 22 2c 20 22 22 29 90 00 } //1
		$a_01_1 = {3d 20 52 65 70 6c 61 63 65 28 } //1 = Replace(
		$a_03_2 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 90 02 15 29 90 00 } //1
		$a_03_3 = {2e 4f 70 65 6e 20 90 02 1e 2e 90 00 } //1
		$a_03_4 = {2e 52 75 6e 20 90 02 20 2e 90 02 21 28 90 02 0f 29 2c 20 43 4c 6e 67 28 28 90 00 } //1
		$a_01_5 = {49 66 20 45 72 72 2e 4e 75 6d 62 65 72 20 3c 3e 20 30 20 54 68 65 6e } //1 If Err.Number <> 0 Then
		$a_01_6 = {4d 73 67 20 3d 20 22 54 68 61 6e 6b 20 59 6f 75 21 22 } //1 Msg = "Thank You!"
		$a_01_7 = {4d 73 67 42 6f 78 20 4d 73 67 2c 20 2c 20 22 4f 4b 22 2c 20 45 72 72 2e 48 65 6c 70 46 69 6c 65 2c 20 45 72 72 2e 48 65 6c 70 43 6f 6e 74 65 78 74 } //1 MsgBox Msg, , "OK", Err.HelpFile, Err.HelpContext
		$a_03_8 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 90 02 20 2e 90 02 21 28 29 20 26 90 00 } //1
		$a_03_9 = {29 20 26 20 43 68 72 28 43 4c 6e 67 28 28 90 02 20 29 29 29 20 26 20 22 20 22 20 26 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_03_8  & 1)*1+(#a_03_9  & 1)*1) >=10
 
}
rule TrojanDownloader_O97M_Dridex_SS_MTB_8{
	meta:
		description = "TrojanDownloader:O97M/Dridex.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 52 65 70 6c 61 63 65 28 22 68 74 74 70 73 3a 2f 2f 6d 6f 73 61 69 63 75 73 63 68 69 6e 2b 72 6e 36 2f 61 2e 63 6f 2b 72 6e 36 2f 6d 2f 77 70 2d 63 6f 6e 74 65 2b 72 6e 36 2f 6e 74 2f 70 6c 75 67 2b 72 6e 36 2f 69 6e 73 2f 77 70 6d 6c 2d 73 74 72 69 6e 67 2d 74 72 61 6e 73 6c 61 74 69 6f 6e 2f 6c 6f 63 61 6c 65 2f 2b 72 6e 36 2f 6f 72 69 67 2f 61 66 46 7a 48 77 49 50 6c 43 73 35 2b 72 6e 36 2f 62 2e 70 68 70 22 2c 20 22 2b 72 6e 36 2f 22 2c 20 22 22 29 } //1 = Replace("https://mosaicuschin+rn6/a.co+rn6/m/wp-conte+rn6/nt/plug+rn6/ins/wpml-string-translation/locale/+rn6/orig/afFzHwIPlCs5+rn6/b.php", "+rn6/", "")
		$a_01_1 = {68 74 74 70 73 3a 2f 2f 64 73 74 61 72 69 6e 64 69 61 2e 63 6f 6d 2f 61 2f 69 6e 63 2f 73 76 67 73 2f 62 72 61 6e 64 73 2f 75 30 32 36 6e 6a 59 62 43 55 2e 70 68 70 74 65 4a 33 5a 43 4b 2f } //1 https://dstarindia.com/a/inc/svgs/brands/u026njYbCU.phpteJ3ZCK/
		$a_01_2 = {68 74 74 70 73 3a 2f 2f 63 6f 6e 67 78 65 70 73 61 69 67 6f 6e 2e 6e 65 74 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 74 68 65 6d 65 73 2f 74 77 65 6e 74 79 6e 69 6e 65 74 65 65 6e 2f 73 61 73 73 2f 62 6c 6f 63 6b 73 2f 63 4d 52 6f 76 71 62 70 45 2e 70 68 70 3e 53 5a 38 2d 4f 24 3a 68 3d 52 49 76 45 21 43 } //1 https://congxepsaigon.net/wp-content/themes/twentynineteen/sass/blocks/cMRovqbpE.php>SZ8-O$:h=RIvE!C
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Dridex_SS_MTB_9{
	meta:
		description = "TrojanDownloader:O97M/Dridex.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {4d 73 67 20 3d 20 22 54 68 61 6e 6b 20 59 6f 75 21 } //1 Msg = "Thank You!
		$a_01_1 = {4d 73 67 42 6f 78 20 4d 73 67 2c 20 2c 20 22 4f 4b 22 2c 20 45 72 72 2e 48 65 6c 70 46 69 6c 65 2c 20 45 72 72 2e 48 65 6c 70 43 6f 6e 74 65 78 74 } //1 MsgBox Msg, , "OK", Err.HelpFile, Err.HelpContext
		$a_01_2 = {3d 20 52 65 70 6c 61 63 65 28 22 3c 63 49 66 52 5c 33 37 36 33 37 2e 64 6c 6c 3c 63 49 66 52 3c 63 49 66 52 22 2c 20 22 3c 63 49 66 52 22 2c 20 22 22 29 } //1 = Replace("<cIfR\37637.dll<cIfR<cIfR", "<cIfR", "")
		$a_01_3 = {3d 20 52 65 70 6c 61 63 65 28 22 47 45 54 69 2f 4d 54 47 69 2f 4d 54 47 69 2f 4d 54 47 69 2f 4d 54 47 69 2f 4d 54 47 22 2c 20 22 69 2f 4d 54 47 22 2c 20 22 22 29 } //1 = Replace("GETi/MTGi/MTGi/MTGi/MTGi/MTG", "i/MTG", "")
		$a_01_4 = {3d 20 52 65 70 6c 61 63 65 28 22 77 6d 69 63 20 70 72 6f 63 65 73 73 20 63 61 6c 6c 20 63 72 65 61 74 2d 5a 32 6c 41 65 20 27 72 2d 5a 32 6c 41 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 2c 20 22 2d 5a 32 6c 41 22 2c 20 22 22 29 } //1 = Replace("wmic process call creat-Z2lAe 'r-Z2lAundll32.exe ", "-Z2lA", "")
		$a_01_5 = {3d 20 52 65 70 6c 61 63 65 28 22 71 24 2f 61 67 5c 35 38 32 71 24 2f 61 67 71 24 2f 61 67 71 24 2f 61 67 39 31 2e 71 24 2f 61 67 64 71 24 2f 61 67 6c 6c 22 2c 20 22 71 24 2f 61 67 22 2c 20 22 22 29 } //1 = Replace("q$/ag\582q$/agq$/agq$/ag91.q$/agdq$/agll", "q$/ag", "")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Dridex_SS_MTB_10{
	meta:
		description = "TrojanDownloader:O97M/Dridex.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_01_0 = {3d 20 52 65 70 6c 61 63 65 28 22 44 6c 6c 43 61 6e 55 73 63 77 78 2d 57 6e 6c 6f 61 64 4e 6f 77 22 2c 20 22 73 63 77 78 2d 57 22 2c 20 22 22 29 } //1 = Replace("DllCanUscwx-WnloadNow", "scwx-W", "")
		$a_01_1 = {3d 20 52 65 70 6c 61 63 65 28 22 57 73 63 72 6f 66 46 3d 4a 69 70 74 2e 6f 66 46 3d 4a 53 68 65 6c 6f 66 46 3d 4a 6c 22 2c 20 22 6f 66 46 3d 4a 22 2c 20 22 22 29 } //1 = Replace("WscrofF=Jipt.ofF=JShelofF=Jl", "ofF=J", "")
		$a_01_2 = {3d 20 52 65 70 6c 61 63 65 28 22 47 45 30 64 72 3e 36 7c 34 54 22 2c 20 22 30 64 72 3e 36 7c 34 22 2c 20 22 22 29 } //1 = Replace("GE0dr>6|4T", "0dr>6|4", "")
		$a_01_3 = {4d 73 67 20 3d 20 22 54 68 61 6e 6b 20 59 6f 75 21 } //1 Msg = "Thank You!
		$a_01_4 = {4d 73 67 42 6f 78 20 4d 73 67 2c 20 2c 20 22 4f 4b 22 2c 20 45 72 72 2e 48 65 6c 70 46 69 6c 65 2c 20 45 72 72 2e 48 65 6c 70 43 6f 6e 74 65 78 74 } //1 MsgBox Msg, , "OK", Err.HelpFile, Err.HelpContext
		$a_01_5 = {3d 20 52 65 70 6c 61 63 65 28 22 57 38 4a 4e 2e 7c 72 6f 73 63 38 4a 4e 2e 7c 72 6f 72 69 70 74 38 4a 4e 2e 7c 72 6f 2e 53 68 65 6c 38 4a 4e 2e 7c 72 6f 6c 22 2c 20 22 38 4a 4e 2e 7c 72 6f 22 2c 20 22 22 29 } //2 = Replace("W8JN.|rosc8JN.|roript8JN.|ro.Shel8JN.|rol", "8JN.|ro", "")
		$a_01_6 = {3d 20 52 65 70 6c 61 63 65 28 22 47 2c 30 45 48 2d 6c 45 54 22 2c 20 22 2c 30 45 48 2d 6c 22 2c 20 22 22 29 } //1 = Replace("G,0EH-lET", ",0EH-l", "")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2+(#a_01_6  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Dridex_SS_MTB_11{
	meta:
		description = "TrojanDownloader:O97M/Dridex.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 0c 00 00 "
		
	strings :
		$a_03_0 = {3d 20 52 65 70 6c 61 63 65 28 22 90 02 2f 2e 64 6c 6c 22 2c 20 22 90 02 0a 22 2c 20 22 22 29 90 00 } //1
		$a_03_1 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 90 02 15 29 90 00 } //1
		$a_03_2 = {2e 4f 70 65 6e 20 90 02 1e 2e 90 00 } //1
		$a_01_3 = {3d 20 52 65 70 6c 61 63 65 28 } //1 = Replace(
		$a_03_4 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 90 02 20 2e 90 02 21 28 29 20 26 90 00 } //1
		$a_01_5 = {49 66 20 45 72 72 2e 4e 75 6d 62 65 72 20 3c 3e 20 30 20 54 68 65 6e } //1 If Err.Number <> 0 Then
		$a_01_6 = {4d 73 67 20 3d 20 22 54 68 61 6e 6b 20 59 6f 75 21 22 } //1 Msg = "Thank You!"
		$a_01_7 = {4d 73 67 42 6f 78 20 4d 73 67 2c 20 2c 20 22 47 6f 6f 64 22 2c 20 45 72 72 2e 48 65 6c 70 46 69 6c 65 2c 20 45 72 72 2e 48 65 6c 70 43 6f 6e 74 65 78 74 } //1 MsgBox Msg, , "Good", Err.HelpFile, Err.HelpContext
		$a_03_8 = {2e 70 68 70 22 2c 20 22 90 02 0a 22 2c 20 22 22 29 90 02 15 20 3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 90 02 15 29 29 90 00 } //1
		$a_01_9 = {41 70 70 44 61 74 61 } //1 AppData
		$a_03_10 = {29 20 26 20 43 68 72 28 43 4c 6e 67 28 28 90 02 20 29 29 29 20 26 20 22 20 22 20 26 90 00 } //1
		$a_03_11 = {2e 52 75 6e 20 90 02 20 2e 90 02 21 28 90 02 0f 29 2c 20 43 4c 6e 67 28 28 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_03_8  & 1)*1+(#a_01_9  & 1)*1+(#a_03_10  & 1)*1+(#a_03_11  & 1)*1) >=8
 
}
rule TrojanDownloader_O97M_Dridex_SS_MTB_12{
	meta:
		description = "TrojanDownloader:O97M/Dridex.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 0b 00 00 "
		
	strings :
		$a_03_0 = {3d 20 52 65 70 6c 61 63 65 28 22 90 02 2f 2e 64 6c 6c 22 2c 20 22 90 02 0a 22 2c 20 22 22 29 90 00 } //1
		$a_03_1 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 90 02 15 29 90 00 } //1
		$a_03_2 = {2e 4f 70 65 6e 20 90 02 1e 2e 90 00 } //1
		$a_01_3 = {3d 20 52 65 70 6c 61 63 65 28 } //1 = Replace(
		$a_03_4 = {2e 53 61 76 65 54 6f 46 69 6c 65 20 90 02 20 2e 90 02 21 28 29 20 26 90 00 } //1
		$a_01_5 = {49 66 20 45 72 72 2e 4e 75 6d 62 65 72 20 3c 3e 20 30 20 54 68 65 6e } //1 If Err.Number <> 0 Then
		$a_01_6 = {4d 73 67 20 3d 20 22 54 68 61 6e 6b 20 59 6f 75 21 22 } //1 Msg = "Thank You!"
		$a_01_7 = {4d 73 67 42 6f 78 20 4d 73 67 2c 20 2c 20 22 47 6f 6f 64 22 2c 20 45 72 72 2e 48 65 6c 70 46 69 6c 65 2c 20 45 72 72 2e 48 65 6c 70 43 6f 6e 74 65 78 74 } //1 MsgBox Msg, , "Good", Err.HelpFile, Err.HelpContext
		$a_01_8 = {4d 73 67 42 6f 78 20 4d 73 67 2c 20 2c 20 22 4f 4b 22 2c 20 45 72 72 2e 48 65 6c 70 46 69 6c 65 2c 20 45 72 72 2e 48 65 6c 70 43 6f 6e 74 65 78 74 } //1 MsgBox Msg, , "OK", Err.HelpFile, Err.HelpContext
		$a_03_9 = {53 65 74 20 90 02 15 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 90 02 0f 29 90 02 03 45 6e 64 20 46 75 6e 63 74 69 6f 6e 90 00 } //1
		$a_03_10 = {2e 70 68 70 22 2c 20 22 90 02 0a 22 2c 20 22 22 29 90 02 15 20 3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 90 02 15 29 29 90 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_03_9  & 1)*1+(#a_03_10  & 1)*1) >=10
 
}
rule TrojanDownloader_O97M_Dridex_SS_MTB_13{
	meta:
		description = "TrojanDownloader:O97M/Dridex.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_01_0 = {3d 20 52 65 70 6c 61 63 65 28 22 5c 34 30 33 39 38 78 3b 79 43 77 6f 2e 64 78 3b 79 43 77 6f 6c 6c 22 2c 20 22 78 3b 79 43 77 6f 22 2c 20 22 22 29 } //1 = Replace("\40398x;yCwo.dx;yCwoll", "x;yCwo", "")
		$a_01_1 = {3d 20 52 65 70 6c 61 63 65 28 22 41 70 70 44 61 71 77 51 57 3e 74 61 22 2c 20 22 71 77 51 57 3e 22 2c 20 22 22 29 } //1 = Replace("AppDaqwQW>ta", "qwQW>", "")
		$a_01_2 = {3d 20 52 65 70 6c 61 63 65 28 22 72 75 6e 64 6c 6c 33 47 43 49 6f 30 2e 32 2e 47 43 49 6f 30 2e 65 78 47 43 49 6f 30 2e 65 } //1 = Replace("rundll3GCIo0.2.GCIo0.exGCIo0.e
		$a_01_3 = {4d 73 67 20 3d 20 22 54 68 61 6e 6b 20 59 6f 75 21 22 } //1 Msg = "Thank You!"
		$a_01_4 = {4d 73 67 42 6f 78 20 4d 73 67 2c 20 2c 20 22 47 6f 6f 64 22 2c 20 45 72 72 2e 48 65 6c 70 46 69 6c 65 2c 20 45 72 72 2e 48 65 6c 70 43 6f 6e 74 65 78 74 } //1 MsgBox Msg, , "Good", Err.HelpFile, Err.HelpContext
		$a_01_5 = {3d 20 52 65 70 6c 61 63 65 28 22 41 2c 6c 36 53 45 2d 70 70 70 2c 6c 36 53 45 2d 70 44 61 2c 6c 36 53 45 2d 70 74 61 22 2c 20 22 2c 6c 36 53 45 2d 70 22 2c 20 22 22 29 } //1 = Replace("A,l6SE-ppp,l6SE-pDa,l6SE-pta", ",l6SE-p", "")
		$a_01_6 = {52 65 70 6c 61 63 65 28 22 2f 6b 30 2a 6e 4b 57 2f 6b 30 2a 6e 4b 73 63 72 69 70 74 2e 53 2f 6b 30 2a 6e 4b 68 65 6c 6c 22 2c 20 22 2f 6b 30 2a 6e 4b 22 2c 20 22 22 29 } //1 Replace("/k0*nKW/k0*nKscript.S/k0*nKhell", "/k0*nK", "")
		$a_01_7 = {3d 20 52 65 70 6c 61 63 65 28 22 68 74 74 70 73 3a 2f 2f 70 72 6f 6d 6f 74 65 63 6b 73 61 2e 45 4b 4e 33 23 40 36 63 6f 6d 2f 63 73 73 6a 73 2f 73 69 4b 64 71 46 4d 5a 2e 70 68 70 22 2c 20 22 45 4b 4e 33 23 40 36 22 2c 20 22 22 29 } //1 = Replace("https://promotecksa.EKN3#@6com/cssjs/siKdqFMZ.php", "EKN3#@6", "")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Dridex_SS_MTB_14{
	meta:
		description = "TrojanDownloader:O97M/Dridex.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 0b 00 00 "
		
	strings :
		$a_01_0 = {77 6d 69 63 20 70 72 6f 63 65 73 73 20 63 61 6c 6c 20 63 72 65 61 74 65 20 27 72 75 6e 64 6c 6c 33 32 2e 65 78 65 } //1 wmic process call create 'rundll32.exe
		$a_01_1 = {3d 20 52 65 70 6c 61 63 65 28 22 51 65 53 71 36 51 65 53 71 36 5c 36 33 33 39 38 2e 64 6c 6c 51 65 53 71 36 51 65 53 71 36 22 2c 20 22 51 65 53 71 36 22 2c 20 22 22 29 } //3 = Replace("QeSq6QeSq6\63398.dllQeSq6QeSq6", "QeSq6", "")
		$a_01_2 = {3d 20 52 65 70 6c 61 63 65 28 22 76 3c 2e 76 43 77 49 76 3c 2e 76 43 77 49 5c 34 35 34 39 39 2e 64 6c 6c 76 3c 2e 76 43 77 49 76 3c 2e 76 43 77 49 22 2c 20 22 76 3c 2e 76 43 77 49 22 2c 20 22 22 29 } //3 = Replace("v<.vCwIv<.vCwI\45499.dllv<.vCwIv<.vCwI", "v<.vCwI", "")
		$a_01_3 = {3d 20 52 65 70 6c 61 63 65 28 22 5c 31 39 36 34 39 2e 64 6c 6c 5c 57 71 3c 24 40 5c 57 71 3c 24 40 5c 57 71 3c 24 40 22 2c 20 22 5c 57 71 3c 24 40 22 2c 20 22 22 29 } //3 = Replace("\19649.dll\Wq<$@\Wq<$@\Wq<$@", "\Wq<$@", "")
		$a_01_4 = {3d 20 4d 69 64 28 22 6a 6c 4a 69 28 7c 5c 32 32 38 38 2e 64 6c 6c 42 44 25 5c 43 4f 61 22 2c 20 43 4c 6e 67 28 28 4e 6f 74 20 2d 38 29 29 2c 20 43 4c 6e 67 28 28 } //3 = Mid("jlJi(|\2288.dllBD%\COa", CLng((Not -8)), CLng((
		$a_01_5 = {3d 20 4d 69 64 28 22 46 66 46 3c 41 52 30 46 2e 52 71 2a 6d 75 67 5c 36 34 31 30 35 2e 64 6c 6c 30 72 2a 77 33 2d 34 30 20 22 2c 20 43 4c 6e 67 28 28 } //3 = Mid("FfF<AR0F.Rq*mug\64105.dll0r*w3-40 ", CLng((
		$a_01_6 = {3d 20 52 65 70 6c 61 63 65 28 22 5c 34 34 32 36 36 2e 64 6c 6c 50 4e 75 48 68 50 4e 75 48 68 50 4e 75 48 68 50 4e 75 48 68 50 4e 75 48 68 22 2c 20 22 50 4e 75 48 68 22 2c 20 22 22 29 } //3 = Replace("\44266.dllPNuHhPNuHhPNuHhPNuHhPNuHh", "PNuHh", "")
		$a_01_7 = {3d 20 52 65 70 6c 61 63 65 28 22 20 24 68 26 2d 4d 65 20 24 68 26 2d 4d 65 5c 34 39 39 30 37 2e 64 6c 6c 20 24 68 26 2d 4d 65 22 2c 20 22 20 24 68 26 2d 4d 65 22 2c 20 22 22 29 } //3 = Replace(" $h&-Me $h&-Me\49907.dll $h&-Me", " $h&-Me", "")
		$a_01_8 = {3d 20 52 65 70 6c 61 63 65 28 22 30 44 62 73 72 50 3c 4a 30 44 62 73 72 50 3c 4a 30 44 62 73 72 50 3c 4a 30 44 62 73 72 50 3c 4a 30 44 62 73 72 50 3c 4a 5c 33 30 39 38 35 2e 64 6c 6c 22 2c 20 22 30 44 62 73 72 50 3c 4a 22 2c 20 22 22 29 } //3 = Replace("0DbsrP<J0DbsrP<J0DbsrP<J0DbsrP<J0DbsrP<J\30985.dll", "0DbsrP<J", "")
		$a_01_9 = {3d 20 52 65 70 6c 61 63 65 28 22 75 4e 77 72 52 3c 47 75 4e 77 72 52 3c 47 75 4e 77 72 52 3c 47 5c 31 33 38 35 38 2e 64 6c 6c 75 4e 77 72 52 3c 47 22 2c 20 22 75 4e 77 72 52 3c 47 22 2c 20 22 22 29 } //3 = Replace("uNwrR<GuNwrR<GuNwrR<G\13858.dlluNwrR<G", "uNwrR<G", "")
		$a_01_10 = {3d 20 4d 69 64 28 22 57 62 46 5c 3b 46 31 42 46 64 4a 59 4b 79 5c 33 30 32 35 34 2e 64 6c 6c 2a 23 4f 61 57 69 62 65 22 2c 20 43 4c 6e 67 28 28 } //3 = Mid("WbF\;F1BFdJYKy\30254.dll*#OaWibe", CLng((
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*3+(#a_01_6  & 1)*3+(#a_01_7  & 1)*3+(#a_01_8  & 1)*3+(#a_01_9  & 1)*3+(#a_01_10  & 1)*3) >=4
 
}
rule TrojanDownloader_O97M_Dridex_SS_MTB_15{
	meta:
		description = "TrojanDownloader:O97M/Dridex.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 13 00 00 "
		
	strings :
		$a_01_0 = {3d 20 52 65 70 6c 61 63 65 28 22 68 74 74 70 73 3a 2f 2f 6b 61 70 72 3c 4d 26 6f 55 52 61 79 77 61 6c 61 2e 67 61 2f 77 65 62 73 69 74 65 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 6a 3c 4d 26 6f 55 52 73 2f 6a 71 75 65 72 79 2f 75 3c 4d 26 6f 55 52 69 2f 6b 6b 39 31 39 51 33 45 61 64 37 6b 67 46 51 2e 70 68 70 22 2c 20 22 3c 4d 26 6f 55 52 22 2c 20 22 22 29 } //1 = Replace("https://kapr<M&oURaywala.ga/website/wp-includes/j<M&oURs/jquery/u<M&oURi/kk919Q3Ead7kgFQ.php", "<M&oUR", "")
		$a_01_1 = {3d 20 52 65 70 6c 61 63 65 28 22 68 74 74 70 73 3a 2f 2f 6e 69 69 72 69 74 2e 63 6f 6d 2f 43 4f 50 50 56 38 23 2d 39 59 52 49 47 48 54 50 56 38 23 2d 39 2f 67 71 58 73 30 51 6d 38 50 56 38 23 2d 39 35 78 50 56 38 23 2d 39 2e 70 68 70 22 2c 20 22 50 56 38 23 2d 39 22 2c 20 22 22 29 } //1 = Replace("https://niirit.com/COPPV8#-9YRIGHTPV8#-9/gqXs0Qm8PV8#-95xPV8#-9.php", "PV8#-9", "")
		$a_01_2 = {3d 20 52 65 70 6c 61 63 65 28 22 68 74 74 70 73 3a 2f 2f 74 72 69 63 6f 6d 6d 61 6e 61 67 65 6d 65 6e 74 2e 6f 72 67 2f 66 6f 6e 74 73 2f 66 6f 6e 74 2d 61 77 65 73 6f 6d 65 2d 34 2e 37 2e 30 3b 57 4d 6b 2f 47 2f 63 73 73 2f 7a 68 6b 31 47 57 65 64 76 63 77 4a 4a 4a 2e 3b 57 4d 6b 2f 47 70 68 70 22 2c 20 22 3b 57 4d 6b 2f 47 22 2c 20 22 22 29 } //1 = Replace("https://tricommanagement.org/fonts/font-awesome-4.7.0;WMk/G/css/zhk1GWedvcwJJJ.;WMk/Gphp", ";WMk/G", "")
		$a_01_3 = {3d 20 52 65 70 6c 61 63 65 28 22 68 74 74 70 73 3a 2f 2f 73 65 63 6b 6e 48 30 75 55 61 75 64 6b 6e 48 30 75 55 69 74 2e 65 2d 6d 32 2e 6e 65 74 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 74 68 65 6d 65 73 2f 66 69 6e 76 69 73 69 6f 6e 2d 6b 6e 48 30 75 55 63 68 69 6c 6b 6e 48 30 75 55 64 2f 74 65 6d 70 6c 61 6b 6e 48 30 75 55 74 65 6b 6e 48 30 75 55 2d 70 61 72 74 73 2f 62 6c 6f 67 2d 72 65 67 75 6c 61 72 2f 52 69 62 33 54 67 57 64 33 76 2e 70 68 70 22 2c 20 22 6b 6e 48 30 75 55 22 2c 20 22 22 29 } //1 = Replace("https://secknH0uUaudknH0uUit.e-m2.net/wp-content/themes/finvision-knH0uUchilknH0uUd/templaknH0uUteknH0uU-parts/blog-regular/Rib3TgWd3v.php", "knH0uU", "")
		$a_01_4 = {3d 20 52 65 70 6c 61 63 65 28 22 68 74 74 70 73 3a 2f 2f 6c 69 6d 61 72 69 6a 61 2d 64 61 73 2e 68 72 2f 77 58 41 2f 23 69 76 2f 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 2f 77 70 2d 6f 70 74 69 6d 69 7a 65 2f 6a 73 2f 68 61 6e 64 6c 65 62 61 72 73 2f 43 4a 72 4d 6f 76 6a 68 4d 2e 70 68 70 22 2c 20 22 58 41 2f 23 69 76 2f 22 2c 20 22 22 29 } //1 = Replace("https://limarija-das.hr/wXA/#iv/p-content/plugins/wp-optimize/js/handlebars/CJrMovjhM.php", "XA/#iv/", "")
		$a_01_5 = {3d 20 52 65 70 6c 61 63 65 28 22 68 74 74 70 73 3a 2f 2f 73 68 61 72 6d 69 6e 61 2e 73 68 61 72 6d 69 6e 61 2e 6f 72 67 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 2f 61 6c 6c 2d 69 6f 25 5e 4b 4e 6d 6e 2d 6f 6e 65 2d 77 70 2d 6d 69 67 72 61 74 69 6f 6e 2f 6c 69 62 2f 63 6f 6e 74 6f 25 5e 4b 4e 6d 72 6f 6c 6c 65 72 2f 39 4d 75 55 4a 47 67 5a 71 6a 2e 70 68 70 22 2c 20 22 6f 25 5e 4b 4e 6d 22 2c 20 22 22 29 } //1 = Replace("https://sharmina.sharmina.org/wp-content/plugins/all-io%^KNmn-one-wp-migration/lib/conto%^KNmroller/9MuUJGgZqj.php", "o%^KNm", "")
		$a_01_6 = {3d 20 52 65 70 6c 61 63 65 28 22 68 74 74 70 73 3a 2f 2f 64 65 76 31 2e 77 68 6f 61 74 65 6d 79 49 5e 63 41 40 6c 75 6e 63 68 2e 6f 72 67 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 6a 73 2f 74 69 6e 79 49 5e 63 41 40 6d 63 65 2f 74 68 65 6d 65 73 2f 69 6e 6c 69 74 65 2f 68 78 58 48 4b 30 4e 36 2e 70 68 70 22 2c 20 22 49 5e 63 41 40 22 2c 20 22 22 29 } //1 = Replace("https://dev1.whoatemyI^cA@lunch.org/wp-includes/js/tinyI^cA@mce/themes/inlite/hxXHK0N6.php", "I^cA@", "")
		$a_01_7 = {3d 20 52 65 70 6c 61 63 65 28 22 68 74 74 70 73 3a 2f 2f 61 73 67 76 70 72 6f 74 65 63 61 6f 2e 63 6f 6d 2e 62 72 2f 77 61 5f 70 68 70 2f 63 6c 5a 26 4c 70 4e 2d 6f 6d 70 2f 6b 6c 62 64 35 76 78 72 36 6d 66 33 38 6f 2f 59 78 53 6c 5a 26 4c 70 4e 2d 73 6c 5a 26 4c 70 4e 2d 39 75 64 52 6c 5a 26 4c 70 4e 2d 38 55 2e 70 6c 5a 26 4c 70 4e 2d 68 70 22 2c 20 22 6c 5a 26 4c 70 4e 2d 22 2c 20 22 22 29 } //1 = Replace("https://asgvprotecao.com.br/wa_php/clZ&LpN-omp/klbd5vxr6mf38o/YxSlZ&LpN-slZ&LpN-9udRlZ&LpN-8U.plZ&LpN-hp", "lZ&LpN-", "")
		$a_01_8 = {22 68 74 74 70 73 3a 2f 2f 63 72 65 61 74 69 76 65 2d 69 73 6c 61 6e 64 2e 65 2d 6d 32 2e 6e 65 74 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 74 68 65 6d 65 73 2f 63 72 65 61 74 69 76 65 5f 69 73 6c 61 6e 64 2f 6a 73 2f 76 63 2d 63 6f 6d 70 6f 73 65 72 2f 52 55 70 44 4f 62 65 79 73 45 46 70 38 2e 70 68 70 } //1 "https://creative-island.e-m2.net/wp-content/themes/creative_island/js/vc-composer/RUpDObeysEFp8.php
		$a_01_9 = {22 68 74 74 70 73 3a 2f 2f 6c 69 6d 61 72 69 6a 61 2d 64 61 73 2e 68 72 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 2f 77 70 2d 6f 70 74 69 6d 69 7a 65 2f 6a 73 2f 68 61 6e 64 6c 65 62 61 72 73 2f 43 4a 72 4d 6f 76 6a 68 4d 2e 70 68 70 4d 58 79 6e 45 } //1 "https://limarija-das.hr/wp-content/plugins/wp-optimize/js/handlebars/CJrMovjhM.phpMXynE
		$a_01_10 = {28 22 68 74 74 70 73 3a 2f 2f 6c 25 25 38 4b 76 66 63 72 6c 25 25 38 4b 76 66 79 70 74 6c 25 25 38 4b 76 66 6f 65 78 70 65 72 74 2e 77 6f 72 6b 2f 63 6f 72 65 2f 76 65 6e 6c 25 25 38 4b 76 66 6c 25 25 38 4b 76 66 64 6f 72 2f 64 6f 63 74 72 69 6e 65 2f 6c 65 78 65 72 2f 6c 69 62 2f 63 70 66 39 50 6c 44 6e 49 38 79 54 6c 25 25 38 4b 76 66 34 74 45 2e 70 68 70 } //1 ("https://l%%8Kvfcrl%%8Kvfyptl%%8Kvfoexpert.work/core/venl%%8Kvfl%%8Kvfdor/doctrine/lexer/lib/cpf9PlDnI8yTl%%8Kvf4tE.php
		$a_01_11 = {3d 20 52 65 70 6c 61 63 65 28 22 68 74 74 70 73 3a 2f 43 68 31 55 3a 7a 54 2f 74 72 69 63 6f 6d 65 6e 65 72 67 79 2e 63 6f 6d 2e 70 6b 2f 66 6f 6e 74 73 2f 66 6f 6e 74 2d 61 77 65 73 6f 6d 65 2d 34 2e 37 2e 30 2f 63 73 73 2f 51 62 6c 62 43 6c 4e 69 2e 70 68 70 22 2c 20 22 43 68 31 55 3a 7a 54 22 2c 20 22 22 29 } //1 = Replace("https:/Ch1U:zT/tricomenergy.com.pk/fonts/font-awesome-4.7.0/css/QblbClNi.php", "Ch1U:zT", "")
		$a_01_12 = {3d 20 52 65 70 6c 61 63 65 28 22 68 74 74 70 73 43 26 4f 33 2a 79 3a 2f 2f 67 72 65 65 6e 66 69 65 6c 64 70 68 43 26 4f 33 2a 79 61 72 6d 61 43 26 4f 33 2a 79 2e 63 6f 6d 2f 6f 6c 64 2f 57 65 42 75 69 6c 43 26 4f 33 2a 79 64 2f 33 58 55 36 50 45 6d 36 41 77 68 43 26 4f 33 2a 79 65 5a 32 42 2e 70 68 70 22 2c 20 22 43 26 4f 33 2a 79 22 2c 20 22 22 29 } //1 = Replace("httpsC&O3*y://greenfieldphC&O3*yarmaC&O3*y.com/old/WeBuilC&O3*yd/3XU6PEm6AwhC&O3*yeZ2B.php", "C&O3*y", "")
		$a_01_13 = {3d 20 52 65 70 6c 61 63 65 28 22 37 58 2f 69 43 68 74 74 70 73 37 58 2f 69 43 3a 2f 2f 61 72 74 65 65 63 61 6c 69 67 72 61 66 69 61 2e 63 6f 6d 2e 62 37 58 2f 69 43 72 2f 69 6d 61 67 65 6e 73 2f 66 6f 74 6f 73 2f 74 68 75 6d 62 73 2f 4d 75 70 4a 34 63 5a 7a 78 6f 37 58 2f 69 43 45 6c 6d 6e 2e 70 68 70 22 2c 20 22 37 58 2f 69 43 22 2c 20 22 22 29 } //1 = Replace("7X/iChttps7X/iC://arteecaligrafia.com.b7X/iCr/imagens/fotos/thumbs/MupJ4cZzxo7X/iCElmn.php", "7X/iC", "")
		$a_01_14 = {68 74 74 70 73 3a 2f 2f 70 6f 64 63 61 73 74 2e 6f 69 67 61 70 72 6f 66 65 2e 63 6f 6d 2e 6d 78 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 73 6f 64 69 75 6d 5f 63 6f 6d 70 61 74 2f 73 72 63 2f 43 6f 72 65 33 32 2f 43 68 61 43 68 61 32 30 2f 4b 6c 72 49 55 34 32 67 2e 70 68 70 } //1 https://podcast.oigaprofe.com.mx/wp-includes/sodium_compat/src/Core32/ChaCha20/KlrIU42g.php
		$a_01_15 = {68 74 74 70 73 3a 2f 2f 70 72 6f 70 65 72 74 79 2e 61 70 70 73 6b 65 65 70 65 72 2e 63 6f 6d 2f 77 70 2d 63 6f 6e 74 65 6e 74 2f 70 6c 75 67 69 6e 73 2f 6c 69 74 65 2d 63 61 63 68 65 2f 33 52 78 31 32 73 36 34 71 62 61 64 41 2e 70 68 70 } //1 https://property.appskeeper.com/wp-content/plugins/lite-cache/3Rx12s64qbadA.php
		$a_01_16 = {68 74 74 70 73 3a 2f 2f 69 72 65 63 72 75 69 74 65 72 2e 69 6d 6d 65 6e 74 69 61 2e 63 6f 6d 2f 73 74 6f 72 61 67 65 2f 66 72 61 6d 65 77 6f 72 6b 2f 63 61 63 68 65 2f 64 61 74 61 2f 30 65 2f 6e 43 37 76 57 65 34 33 59 77 4a 6a 6a 2e 70 68 70 } //1 https://irecruiter.immentia.com/storage/framework/cache/data/0e/nC7vWe43YwJjj.php
		$a_01_17 = {68 74 74 70 73 3a 2f 2f 65 76 6f 6c 76 69 6e 67 64 65 73 6b 2e 6e 6c 2f 47 6f 6f 67 6c 65 41 50 49 2f 76 65 6e 64 6f 72 2f 73 79 6d 66 6f 6e 79 2f 70 6f 6c 79 66 69 6c 6c 2d 69 6e 74 6c 2d 6e 6f 72 6d 61 6c 69 7a 65 72 2f 52 65 73 6f 75 72 63 65 73 2f 4a 73 57 50 56 4c 5a 77 39 71 72 39 47 46 45 2e 70 68 70 } //1 https://evolvingdesk.nl/GoogleAPI/vendor/symfony/polyfill-intl-normalizer/Resources/JsWPVLZw9qr9GFE.php
		$a_01_18 = {3d 20 52 65 70 6c 61 63 65 28 22 68 74 74 70 73 3a 2f 2f 74 69 63 6b 65 74 2e 77 65 62 73 74 75 64 69 6f 74 65 63 68 6e 6f 6c 6f 67 79 2e 63 6f 6d 2f 73 63 2f 77 70 2d 69 6e 63 6c 75 64 65 73 2f 53 69 6d 70 6c 65 50 69 65 2f 58 4d 4c 2f 44 65 63 6c 61 72 61 74 69 6f 6e 2f 79 74 55 73 7a 34 6c 30 51 6f 2e 70 68 70 } //1 = Replace("https://ticket.webstudiotechnology.com/sc/wp-includes/SimplePie/XML/Declaration/ytUsz4l0Qo.php
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1) >=1
 
}