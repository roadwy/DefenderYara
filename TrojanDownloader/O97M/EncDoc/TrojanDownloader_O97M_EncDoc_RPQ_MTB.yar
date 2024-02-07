
rule TrojanDownloader_O97M_EncDoc_RPQ_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.RPQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {3d 20 22 70 6f 77 5e 65 72 73 22 } //01 00  = "pow^ers"
		$a_01_1 = {3d 20 22 68 65 5e 6c 6c 22 } //01 00  = "he^ll"
		$a_01_2 = {3d 20 22 43 3a 5c 55 73 65 72 73 5c 50 75 62 6c 69 63 5c 44 6f 63 75 6d 65 6e 74 73 5c 67 6f 64 2e 62 61 74 22 } //01 00  = "C:\Users\Public\Documents\god.bat"
		$a_03_3 = {53 65 74 20 90 02 0f 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_EncDoc_RPQ_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.RPQ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 09 00 00 01 00 "
		
	strings :
		$a_01_0 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 3a 2f 2f 6f 72 74 68 6f 6d 61 79 2e 63 6f 6d 2e 62 72 2f 47 44 37 41 33 50 53 44 34 7a 63 2f 74 77 2e 68 74 6d 6c 22 } //01 00  "h"&"t"&"t"&"p"&"s://orthomay.com.br/GD7A3PSD4zc/tw.html"
		$a_01_1 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 3a 2f 2f 71 75 65 62 72 61 64 61 64 69 67 69 74 61 6c 2e 63 6f 6d 2e 62 72 2f 61 67 32 44 56 71 49 4d 2f 77 2e 68 74 6d 6c 22 } //01 00  "h"&"t"&"t"&"p"&"s://quebradadigital.com.br/ag2DVqIM/w.html"
		$a_01_2 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 3a 2f 2f 6d 75 73 74 61 66 61 6b 68 61 66 69 6d 73 70 2e 61 66 2f 55 6e 45 35 6b 4f 6e 58 2f 74 77 2e 68 74 6d 6c 22 } //01 00  "h"&"t"&"t"&"p"&"s://mustafakhafimsp.af/UnE5kOnX/tw.html"
		$a_01_3 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 3a 2f 2f 67 75 70 74 61 2d 66 6f 6f 64 73 2e 78 79 7a 2f 64 54 45 4f 64 4d 42 79 6f 72 69 2f 6a 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c 22 } //01 00  "h"&"t"&"t"&"p"&"://gupta-foods.xyz/dTEOdMByori/j.h"&"t"&"m"&"l"
		$a_01_4 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 3a 2f 2f 67 75 70 74 61 2d 61 69 72 77 61 79 73 2e 69 63 75 2f 4d 53 4f 46 6a 68 30 45 58 52 52 38 2f 6a 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c } //01 00  "h"&"t"&"t"&"p"&"://gupta-airways.icu/MSOFjh0EXRR8/j.h"&"t"&"m"&"l
		$a_03_5 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 3a 2f 2f 67 75 70 74 61 2d 90 02 1f 2e 90 02 05 2f 90 02 0f 2f 90 02 03 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c 90 00 } //01 00 
		$a_01_6 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 22 26 22 2f 2f 69 6c 65 61 64 61 66 72 69 63 61 6e 6f 77 2e 6f 72 67 2f 67 5a 50 5a 62 36 79 4b 2f 6e 32 2e 68 74 6d 6c 22 } //01 00  "h"&"t"&"t"&"p"&"s"&":"&"//ileadafricanow.org/gZPZb6yK/n2.html"
		$a_01_7 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 22 26 22 2f 22 26 22 2f 67 63 6d 68 70 2e 70 73 2f 30 42 44 52 43 4e 38 44 58 6e 2f 6e 33 2e 68 74 6d 6c 22 } //01 00  "h"&"t"&"t"&"p"&"s"&":"&"/"&"/gcmhp.ps/0BDRCN8DXn/n3.html"
		$a_01_8 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 22 26 22 2f 22 26 22 2f 73 65 72 76 69 63 65 65 78 70 72 65 73 73 2e 63 6f 6d 2e 62 72 2f 37 6d 70 42 6d 73 66 6c 62 37 66 65 2f 6e 31 2e 68 74 6d 6c 22 } //00 00  "h"&"t"&"t"&"p"&"s"&":"&"/"&"/serviceexpress.com.br/7mpBmsflb7fe/n1.html"
	condition:
		any of ($a_*)
 
}