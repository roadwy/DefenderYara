
rule TrojanDownloader_O97M_Qakbot_SS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 6f 6e 6c 69 6e 65 63 6f 6d 70 61 6e 69 65 68 6f 75 73 65 2e 63 6f 6d 2f 73 6f 72 76 2e 70 6e 67 } //00 00  https://onlinecompaniehouse.com/sorv.png
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Qakbot_SS_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 63 68 69 6e 61 2e 61 73 69 61 73 70 61 69 6e 2e 63 6f 6d 2f 74 65 72 74 67 65 76 2f } //01 00  http://china.asiaspain.com/tertgev/
		$a_01_1 = {43 3a 5c 54 65 73 74 5c 74 65 73 74 32 5c 46 69 6b 73 61 74 2e 65 78 65 } //01 00  C:\Test\test2\Fiksat.exe
		$a_01_2 = {31 32 34 37 30 31 35 2e 70 6e 67 } //00 00  1247015.png
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Qakbot_SS_MTB_3{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6f 6e 6c 69 6e 65 2d 63 6f 6d 70 61 6e 69 65 73 68 6f 75 73 65 2e 63 6f 6d 2f 69 74 65 2e 70 6e 67 } //01 00  online-companieshouse.com/ite.png
		$a_01_1 = {43 3a 5c 67 6c 69 6d 70 69 5c 64 75 6f 74 2e 70 6f 69 } //01 00  C:\glimpi\duot.poi
		$a_01_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00  DllRegisterServer
		$a_01_3 = {72 75 6e 64 6c 6c 33 32 } //00 00  rundll32
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Qakbot_SS_MTB_4{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,0d 00 0d 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {75 52 6c 4d 6f 6e } //01 00  uRlMon
		$a_01_1 = {43 72 65 61 74 65 44 69 72 65 63 74 6f 72 79 41 } //01 00  CreateDirectoryA
		$a_01_2 = {46 69 6c 65 50 72 6f 74 6f 63 6f 6c 48 61 6e 64 6c 65 72 } //01 00  FileProtocolHandler
		$a_01_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //0a 00  URLDownloadToFileA
		$a_01_4 = {68 74 74 70 3a 2f 2f 62 61 72 74 73 74 6f 70 70 65 6c 2e 63 6f 6d 2f 72 71 66 61 72 64 7a 73 67 69 68 75 2f 35 35 35 35 35 35 35 35 35 2e 70 6e 67 } //0a 00  http://bartstoppel.com/rqfardzsgihu/555555555.png
		$a_01_5 = {68 74 74 70 3a 2f 2f 6f 63 65 61 6e 62 6d 2e 63 61 2f 68 70 70 6c 6f 2f 35 35 35 35 35 35 35 35 35 2e 70 6e 67 } //0a 00  http://oceanbm.ca/hpplo/555555555.png
		$a_01_6 = {68 74 74 70 3a 2f 2f 68 65 61 76 65 6e 6c 79 68 65 61 6c 69 6e 67 68 61 6e 64 73 2e 6f 72 67 2f 62 65 65 7a 78 76 64 73 78 65 2f 35 35 35 35 35 35 35 35 35 2e 70 6e 67 } //0a 00  http://heavenlyhealinghands.org/beezxvdsxe/555555555.png
		$a_01_7 = {68 74 74 70 3a 2f 2f 76 65 74 65 72 61 6e 73 70 6c 75 6d 62 69 6e 67 61 6e 64 73 65 77 65 72 2e 63 6f 6d 2f 72 76 65 76 62 72 70 61 7a 63 67 6a 2f 35 35 35 35 35 35 35 35 35 2e 70 6e 67 } //00 00  http://veteransplumbingandsewer.com/rvevbrpazcgj/555555555.png
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_O97M_Qakbot_SS_MTB_5{
	meta:
		description = "TrojanDownloader:O97M/Qakbot.SS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 15 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 3a 2f 2f 62 61 72 6e 65 74 63 75 74 2e 63 6f 2e 75 6b 2f 53 66 43 51 44 66 59 6a 57 6a 2f 79 2e 68 74 6d 6c } //01 00  h"&"t"&"t"&"p"&"s://barnetcut.co.uk/SfCQDfYjWj/y.html
		$a_01_1 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 2f 2f 6d 69 6e 36 6a 65 6d 62 72 61 6e 61 2e 63 6f 6d 2f 65 61 4d 55 47 41 58 44 74 4a 2f 79 2e 68 74 6d 6c } //01 00  h"&"t"&"t"&"p"&"s"&"://min6jembrana.com/eaMUGAXDtJ/y.html
		$a_01_2 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 3a 2f 2f 62 69 6f 63 6f 6d 6d 2e 63 6f 6d 2e 6d 78 2f 31 4b 74 44 59 4f 55 70 6b 58 6d 31 2f 79 2e 68 74 6d 6c } //01 00  h"&"t"&"t"&"p"&"s://biocomm.com.mx/1KtDYOUpkXm1/y.html
		$a_01_3 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 3a 2f 2f 6d 61 67 6e 61 73 63 61 6b 65 73 2e 63 6f 6d 2e 62 72 2f 61 51 36 6d 4f 35 45 73 46 50 7a 2f 79 68 2e 68 74 6d 6c } //01 00  h"&"t"&"t"&"p"&"s://magnascakes.com.br/aQ6mO5EsFPz/yh.html
		$a_01_4 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 2f 2f 73 68 65 72 77 69 6e 63 6c 6f 74 68 69 6e 67 2e 69 6e 2f 6f 71 78 49 41 5a 66 6f 35 36 7a 2f 79 68 2e 68 74 6d 6c } //01 00  h"&"t"&"t"&"p"&"s"&"://sherwinclothing.in/oqxIAZfo56z/yh.html
		$a_01_5 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 2f 2f 6d 69 63 72 6f 74 65 63 68 7a 61 6d 62 69 61 2e 63 6f 6d 2f 75 74 47 49 31 32 6e 6c 2f 79 68 2e 68 74 6d 6c } //01 00  h"&"t"&"t"&"p"&"s"&"://microtechzambia.com/utGI12nl/yh.html
		$a_01_6 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 2f 2f 6b 6c 65 76 76 72 74 65 63 68 2e 63 6f 6d 2f 7a 78 79 77 4a 41 43 32 34 4b 4a 2f 6a 69 2e 68 74 6d 6c } //01 00  h"&"t"&"t"&"p"&"s"&"://klevvrtech.com/zxywJAC24KJ/ji.html
		$a_01_7 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 2f 2f 73 72 6b 63 61 6d 70 75 73 2e 6f 72 67 2f 4f 59 63 4d 52 4a 62 4c 2f 6a 69 2e 68 74 6d 6c } //01 00  h"&"t"&"t"&"p"&"s"&"://srkcampus.org/OYcMRJbL/ji.html
		$a_01_8 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 2f 2f 72 73 74 65 62 65 74 2e 63 6f 2e 69 64 2f 66 62 6d 4b 6b 36 6e 34 38 47 2f 6a 69 2e 68 74 6d 6c } //01 00  h"&"t"&"t"&"p"&"s"&"://rstebet.co.id/fbmKk6n48G/ji.html
		$a_01_9 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 2f 2f 68 65 61 64 6c 69 6e 65 70 72 6f 64 75 63 74 69 6f 6e 73 2e 72 6f 2f 72 4f 4a 58 36 61 69 37 41 6b 5a 45 2f 6f 70 2e 68 74 6d 6c } //01 00  h"&"t"&"t"&"p"&"s"&"://headlineproductions.ro/rOJX6ai7AkZE/op.html
		$a_01_10 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 2f 2f 6a 72 63 61 70 69 74 61 6c 2e 75 6b 2f 65 66 74 38 67 66 46 71 77 2f 6f 70 2e 68 74 6d 6c } //01 00  h"&"t"&"t"&"p"&"s"&"://jrcapital.uk/eft8gfFqw/op.html
		$a_01_11 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 2f 2f 6c 63 2d 62 69 6c 69 6e 67 75 61 2e 63 6f 6d 2f 38 77 70 39 6b 39 52 50 44 7a 6e 2f 6f 70 2e 68 74 6d 6c } //01 00  h"&"t"&"t"&"p"&"s"&"://lc-bilingua.com/8wp9k9RPDzn/op.html
		$a_01_12 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 2f 2f 70 72 6f 6a 65 63 74 67 6f 72 61 2e 63 6f 6d 2f 68 30 32 6a 4d 6f 36 65 7a 2f 6c 69 2e 68 74 6d 6c } //01 00  h"&"t"&"t"&"p"&"s"&"://projectgora.com/h02jMo6ez/li.html
		$a_01_13 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 2f 2f 74 77 6f 62 75 64 67 65 74 74 72 61 76 65 6c 65 72 73 2e 63 6f 6d 2f 46 39 41 4f 64 4c 44 67 6e 37 45 2f 6c 69 2e 68 74 6d 6c } //01 00  h"&"t"&"t"&"p"&"s"&"://twobudgettravelers.com/F9AOdLDgn7E/li.html
		$a_01_14 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 2f 2f 73 6f 72 69 6e 67 65 73 70 72 69 6e 67 73 2e 63 6f 6d 2f 46 4b 68 70 57 53 79 33 76 51 4d 2f 6c 69 2e 68 74 6d 6c } //01 00  h"&"t"&"t"&"p"&"s"&"://soringesprings.com/FKhpWSy3vQM/li.html
		$a_01_15 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 2f 2f 64 6f 73 74 69 72 65 61 6c 74 79 2e 63 6f 2f 50 39 6b 6a 73 38 35 45 4a 42 2f 79 79 31 2e 68 74 6d 6c } //01 00  h"&"t"&"t"&"p"&"s"&"://dostirealty.co/P9kjs85EJB/yy1.html
		$a_01_16 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 2f 2f 67 6f 2e 69 73 63 70 65 6c 73 61 6c 76 61 64 6f 72 2e 6f 72 67 2f 68 78 49 69 30 37 31 78 66 2f 79 79 32 2e 68 74 6d 6c } //01 00  h"&"t"&"t"&"p"&"s"&"://go.iscpelsalvador.org/hxIi071xf/yy2.html
		$a_01_17 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 73 22 26 22 3a 2f 2f 73 79 73 74 65 6d 2e 73 65 76 65 6e 73 65 72 69 65 73 6d 6c 6d 2e 63 6f 6d 2f 41 47 73 78 43 43 65 48 48 70 49 30 2f 79 79 33 2e 68 74 6d 6c } //01 00  h"&"t"&"t"&"p"&"s"&"://system.sevenseriesmlm.com/AGsxCCeHHpI0/yy3.html
		$a_01_18 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 3a 2f 22 26 22 2f 64 6f 22 26 22 63 73 22 26 22 67 79 22 26 22 61 6e 22 26 22 2e 63 22 26 22 6f 22 26 22 6d 2f 77 22 26 22 70 2d 69 22 26 22 6e 22 26 22 63 6c 22 26 22 75 64 22 26 22 65 73 2f 36 71 22 26 22 63 49 } //01 00  h"&"t"&"t"&"p"&":/"&"/do"&"cs"&"gy"&"an"&".c"&"o"&"m/w"&"p-i"&"n"&"cl"&"ud"&"es/6q"&"cI
		$a_01_19 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 3a 2f 22 26 22 2f 70 69 22 26 22 6c 6f 22 26 22 74 73 22 26 22 63 69 22 26 22 65 6e 22 26 22 63 65 22 26 22 2e 63 22 26 22 6f 22 26 22 6d 2f 48 61 22 26 22 6c 69 22 26 22 6d 61 22 26 22 74 2f 32 52 } //01 00  h"&"t"&"t"&"p"&":/"&"/pi"&"lo"&"ts"&"ci"&"en"&"ce"&".c"&"o"&"m/Ha"&"li"&"ma"&"t/2R
		$a_01_20 = {68 22 26 22 74 22 26 22 74 22 26 22 70 22 26 22 3a 2f 2f 6f 22 26 22 6e 65 22 26 22 61 75 22 26 22 64 69 22 26 22 6f 2e 77 22 26 22 6f 72 22 26 22 6c 64 22 26 22 2f 73 75 22 26 22 62 63 22 26 22 6f 6e 22 26 22 73 74 22 26 22 61 62 22 26 22 6c 65 } //00 00  h"&"t"&"t"&"p"&"://o"&"ne"&"au"&"di"&"o.w"&"or"&"ld"&"/su"&"bc"&"on"&"st"&"ab"&"le
	condition:
		any of ($a_*)
 
}