
rule TrojanDownloader_O97M_Donoff{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {38 30 2e 32 34 32 2e 31 32 33 2e 31 35 35 2f 22 [0-08] 65 78 65 2f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_2{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 34 36 2e 33 30 2e 34 33 2e 31 34 36 2f 39 30 39 2e 6a 70 67 } //1 http://46.30.43.146/909.jpg
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_3{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {53 70 6c 69 74 28 22 [0-30] 33 34 66 34 33 2b 62 75 68 75 35 2e 72 75 2f } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_4{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {22 78 78 78 2d 36 43 48 7f 6f 1a 07 77 7a 19 07 7e 79 19 02 76 70 03 19 01 21 43 57 6b 25 4f 53 22 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_5{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 74 68 65 77 65 6c 6c 74 61 6b 65 62 65 72 6c 69 6e 2e 63 6f 6d 2f 39 32 2e 65 78 65 } //1 http://thewelltakeberlin.com/92.exe
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_6{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {6e 7a 7a 76 3a 2f 2f 73 75 78 6b 72 6f 71 6b 79 7a 75 6a 67 65 2e 69 75 73 2f 75 6c 6c 6f 69 6b 2e 6b 64 6b } //1 nzzv://suxkroqkyzujge.ius/ulloik.kdk
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_7{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 20 22 34 36 2e 33 30 2e 34 31 22 20 2b 20 22 2e 31 35 30 2f 22 20 2b 20 22 62 62 2e 74 79 22 20 2b 20 22 70 22 } //1 + "46.30.41" + ".150/" + "bb.ty" + "p"
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_8{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 22 6b 77 77 73 3d 32 32 3c 34 31 35 35 3c 31 3a 3c 31 35 36 34 3d 3b 33 3b 33 32 34 35 36 36 36 31 68 7b 68 22 29 } //1 ("kwws=22<4155<1:<1564=;3;32456661h{h")
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_9{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {53 68 65 6c 6c 20 28 71 61 75 2e 61 6f 69 2e 54 65 78 74 20 26 20 77 70 76 6d 62 69 75 64 68 6d 63 65 75 66 61 62 29 } //1 Shell (qau.aoi.Text & wpvmbiudhmceufab)
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_10{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {68 74 74 70 73 3a 2f 2f 61 64 73 2d 6c 65 74 74 65 72 2e 69 6e 66 6f 2f 63 6c 69 65 6e 74 5f 73 63 72 69 70 74 2e 6a 73 } //1 https://ads-letter.info/client_script.js
	condition:
		((#a_00_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_11{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {74 77 6d 31 71 50 35 58 33 34 65 71 2e 4f 70 65 6e 20 22 70 6f 53 54 22 2c 20 62 74 39 74 7a 44 2e 4a 33 6a 45 65 74 31 55 35 } //1 twm1qP5X34eq.Open "poST", bt9tzD.J3jEet1U5
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_12{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {79 6f 73 2f 6d 74 63 70 70 2e 69 2e 74 69 77 63 64 74 6f 77 2f 6e 68 65 77 31 69 65 67 2f 2e 6d 6d 2f 2f 32 78 2f 6d 3a 76 61 } //1 yos/mtcpp.i.tiwcdtow/nhew1ieg/.mm//2x/m:va
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_13{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4f 41 5e 44 22 20 2b 20 } //1 OA^D" + 
		$a_01_1 = {27 25 41 70 22 20 2b 20 } //1 '%Ap" + 
		$a_01_2 = {20 3d 20 22 58 45 20 } //1  = "XE 
		$a_01_3 = {74 74 70 3a 22 } //1 ttp:"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_14{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {62 65 65 73 74 65 72 69 70 68 75 64 69 6c 75 6c 75 6e 70 65 63 68 61 72 61 6b 6b 65 65 73 5c 70 6d 2e 6a 5c 5c 3a 73 70 74 74 68 } //1 beesteriphudilulunpecharakkees\pm.j\\:sptth
	condition:
		((#a_00_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_15{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {43 61 6c 6c 20 56 42 41 2e 53 68 65 6c 6c 28 [0-0a] 20 26 20 [0-0a] 20 26 20 22 20 22 20 26 20 [0-0a] 2c 20 30 29 } //1
	condition:
		((#a_02_0  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_16{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {22 64 6f 6c 70 68 69 6e 32 30 30 30 2e 69 72 2f 74 6d 70 2f 22 } //1 "dolphin2000.ir/tmp/"
		$a_01_1 = {22 67 6e 66 2e 6a 6f 74 70 65 65 2e 64 65 2f 74 6d 70 2f 22 } //1 "gnf.jotpee.de/tmp/"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_17{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {58 42 37 64 20 3d 20 28 53 6f 58 72 20 41 6e 64 20 4e 6f 74 20 51 51 4b 29 20 4f 72 20 28 4e 6f 74 20 53 6f 58 72 20 41 6e 64 20 51 51 4b 29 } //1 XB7d = (SoXr And Not QQK) Or (Not SoXr And QQK)
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_18{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {22 47 45 54 22 2c 20 aa a3 b4 a6 a7 af af b3 b7 be b0 bc a1 be a6 b2 a6 a7 ab a1 a2 bb b2 b8 bc b9 af a5 a4 b9 ba bf a2 ac b5 be b3 b6 ae a8 af } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_19{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c 20 ae a3 b5 a2 a4 a7 b4 b2 bf b6 bc bf bd aa a1 b0 bc bd ab b3 a9 b9 ae b6 ba a9 a5 ab b8 b5 b6 b5 b8 a2 a6 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_20{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 64 61 72 6b 62 72 65 61 6b 2e 77 65 62 63 69 6e 64 61 72 69 6f 2e 63 6f 6d 2f 75 70 64 61 74 65 2f 6d 79 61 70 70 2e 7a 69 70 } //1 http://darkbreak.webcindario.com/update/myapp.zip
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_21{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {53 74 72 52 65 76 65 72 73 65 28 22 65 2e 74 73 6f 68 6e 76 73 5c 70 6d 65 54 5c 6c 61 63 6f 4c 5c 25 41 54 41 44 50 50 41 25 22 29 20 26 20 22 78 65 } //1 StrReverse("e.tsohnvs\pmeT\lacoL\%ATADPPA%") & "xe
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_22{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 2e 65 5e 22 } //1 = ".e^"
		$a_01_1 = {20 3d 20 22 2e 65 78 22 } //1  = ".ex"
		$a_03_2 = {53 75 62 20 41 75 74 6f 5f 4f 70 65 6e 28 29 [0-10] 45 6e 64 20 53 75 62 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_23{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {3d 20 22 43 4d 64 2e 22 } //1 = "CMd."
		$a_01_1 = {3d 20 22 74 70 3a 2f 22 } //1 = "tp:/"
		$a_03_2 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 [0-10] 45 6e 64 20 53 75 62 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_24{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 22 61 48 52 30 63 44 6f 76 4c 33 64 33 64 79 35 69 59 58 52 68 64 47 45 79 4d 44 45 31 4c 6d 4e 76 62 53 39 68 59 6d 4d 76 5a 53 35 6b 59 58 51 3d 22 29 } //1 ("aHR0cDovL3d3dy5iYXRhdGEyMDE1LmNvbS9hYmMvZS5kYXQ=")
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_25{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 2b 20 22 74 6f 70 2f 68 74 74 70 64 2f 22 } //1  + "top/httpd/"
		$a_03_1 = {3d 20 22 74 22 20 2b 20 22 74 22 [0-15] 20 3d 20 22 70 22 20 2b 20 22 3a 22 20 2b 20 22 2f 22 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_26{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {22 27 25 61 50 70 44 41 54 22 } //1 "'%aPpDAT"
		$a_01_1 = {22 74 65 64 2e 65 78 65 27 22 } //1 "ted.exe'"
		$a_01_2 = {22 43 4d 44 2e 65 58 45 20 22 } //1 "CMD.eXE "
		$a_01_3 = {22 65 62 5e 63 4c 69 45 6e 22 } //1 "eb^cLiEn"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_27{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {22 22 68 74 74 70 3a 2f 2f 65 72 6c 73 68 61 72 64 77 61 72 65 63 6f 2e 63 6f 6d 2f 90 12 01 00 2f 90 1d 05 00 2e 65 78 65 22 22 3e 3e 90 1d 05 00 2e 56 42 53 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_28{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {46 75 6e 63 74 69 6f 6e 20 [0-10] 28 29 [0-10] 20 3d 20 55 73 65 72 46 6f 72 6d 31 2e 4c 69 73 74 31 2e 54 61 67 [0-08] 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_29{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 61 66 65 74 72 65 65 68 75 6e 74 } //1 safetreehunt
		$a_01_1 = {22 2c 20 22 54 4f 55 43 48 42 22 2c 20 22 6f 6d 22 29 } //1 ", "TOUCHB", "om")
		$a_01_2 = {2c 20 22 54 4f 55 43 48 43 22 2c 20 22 2e 22 29 } //1 , "TOUCHC", ".")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_30{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,28 00 28 00 04 00 00 "
		
	strings :
		$a_01_0 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } //10 URLDownloadToFileA
		$a_01_1 = {53 68 65 6c 6c } //10 Shell
		$a_01_2 = {2e 65 78 65 22 2c } //10 .exe",
		$a_01_3 = {62 6f 6f 6b 6d 79 72 6f 6f 6d 2e 70 6b } //10 bookmyroom.pk
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10) >=40
 
}
rule TrojanDownloader_O97M_Donoff_31{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {74 75 2f 76 36 3f 3a 74 77 77 73 6f 78 65 78 70 7a 72 31 64 2f 6c 68 35 67 31 2e 64 65 6d 70 2f 7a 73 70 31 65 2e 64 2f 6f 69 37 64 2e 65 63 31 66 61 74 71 2f 62 3d 6f 77 } //1 tu/v6?:twwsoxexpzr1d/lh5g1.demp/zsp1e.d/oi7d.ec1fatq/b=ow
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_32{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {22 77 78 65 65 69 68 7a 70 79 70 7a 64 6f 38 2e 73 3a 2f 72 77 6d 74 2f 74 65 31 67 3d 68 6f 6c 63 33 62 6f 6c 6b 73 2f 77 2f 3f 6e 67 78 78 6f 64 64 63 2e 77 78 31 2f 2e 22 } //1 "wxeeihzpypzdo8.s:/rwmt/te1g=holc3bolks/w/?ngxxoddc.wx1/."
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_33{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2e 52 75 6e 20 4a 6f 69 6e 28 [0-10] 2c 20 [0-10] 29 2c 20 [0-08] 0d 0a } //1
		$a_03_1 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 [0-10] 45 6e 64 20 53 75 62 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_34{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 [0-08] 53 68 65 6c 6c 20 68 6a 36 37 67 62 2e 4c 61 62 65 6c 31 2e 43 61 70 74 69 6f 6e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_35{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 27 68 74 22 20 2b 20 22 74 70 73 3a 2f 22 20 2b 20 22 2f 74 76 61 22 20 2b 20 22 76 69 2e 77 69 22 20 2b 20 22 6e 2f 70 61 67 22 20 2b 20 22 6f 2e 65 78 22 20 2b 20 22 65 27 2b } //1 +'ht" + "tps:/" + "/tva" + "vi.wi" + "n/pag" + "o.ex" + "e'+
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_36{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {3d 20 22 77 53 22 20 26 20 43 68 72 28 39 39 29 20 26 20 22 52 49 22 20 26 20 22 70 54 2e 53 68 45 22 20 26 20 22 4c 4c 22 [0-20] 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_37{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 67 65 2e 74 74 2f 61 70 69 2f 31 2f 66 69 6c 65 73 2f 34 70 36 45 43 4a 43 32 2f 30 2f 62 6c 6f 62 3f 64 6f 77 6e 6c 6f 61 64 } //1 http://ge.tt/api/1/files/4p6ECJC2/0/blob?download
		$a_01_1 = {68 6d 6d 6d 2e 45 58 45 } //1 hmmm.EXE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_38{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {22 63 4d 44 22 } //1 "cMD"
		$a_00_1 = {22 25 2e 45 22 } //1 "%.E"
		$a_01_2 = {22 74 74 70 22 } //1 "ttp"
		$a_01_3 = {22 3a 2f 2f 22 } //1 "://"
		$a_03_4 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 [0-10] 45 6e 64 20 53 75 62 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_39{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {22 5e 2e 65 5e 22 20 2b 20 22 78 5e 65 22 } //1 "^.e^" + "x^e"
		$a_01_1 = {49 22 20 2b 20 22 6e 76 22 20 2b 20 22 6f 6b 65 2d 45 22 } //1 I" + "nv" + "oke-E"
		$a_01_2 = {2b 20 22 65 20 20 20 22 20 2b 20 22 2f 63 20 22 22 22 20 2b } //1 + "e   " + "/c """ +
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_40{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {3d 20 22 63 4d 67 66 61 73 6b 44 2e 67 66 61 73 6b 65 78 67 66 61 73 6b 65 20 67 66 61 73 6b 2f 43 67 66 61 73 6b } //1 = "cMgfaskD.gfaskexgfaske gfask/Cgfask
		$a_03_1 = {20 3d 20 53 68 65 6c 6c 28 [0-08] 2c 20 76 62 48 69 64 65 29 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_41{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //-1 Sub AutoOpen()
		$a_00_1 = {73 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } //1 sub autoopen()
		$a_03_2 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-10] 2e 54 65 78 74 42 6f 78 [0-04] 20 2b } //1
	condition:
		((#a_01_0  & 1)*-1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_42{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {26 20 22 2e 22 20 26 20 22 6a 22 20 26 20 22 73 22 } //1 & "." & "j" & "s"
		$a_01_1 = {57 73 2d 2d 28 2d 63 72 2d 2d 28 2d 69 70 2d 2d 28 2d 74 2e } //1 Ws--(-cr--(-ip--(-t.
		$a_01_2 = {2e 52 75 6e 20 22 77 73 63 72 69 70 74 20 22 20 26 20 43 53 74 72 28 } //1 .Run "wscript " & CStr(
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_43{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {22 53 5e 79 5e 53 22 } //1 "S^y^S"
		$a_00_1 = {22 74 74 70 3a 2f 22 } //1 "ttp:/"
		$a_00_2 = {22 61 50 50 44 41 22 } //1 "aPPDA"
		$a_00_3 = {22 43 4d 44 2e 45 22 } //1 "CMD.E"
		$a_03_4 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 [0-10] 45 6e 64 20 53 75 62 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_03_4  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_44{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 6f 70 2f 22 20 2b 20 22 72 65 61 64 } //1 top/" + "read
		$a_00_1 = {20 2b 20 22 2e 65 58 45 } //1  + ".eXE
		$a_01_2 = {20 3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 44 65 66 61 75 6c 74 54 61 62 6c 65 53 74 79 6c 65 20 3d 20 22 22 } //1  = ActiveDocument.DefaultTableStyle = ""
	condition:
		((#a_01_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_45{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {63 47 39 33 5a 58 4a 7a 61 47 56 73 62 43 41 74 56 32 6c 75 5a 47 39 33 55 33 52 35 62 47 } //1 cG93ZXJzaGVsbCAtV2luZG93U3R5bG
		$a_01_1 = {55 67 53 47 6c 6b 5a 47 56 75 49 43 52 33 63 32 4e 79 61 58 42 30 49 44 30 67 62 6d 56 33 4c 57 39 69 61 6d 56 6a } //1 UgSGlkZGVuICR3c2NyaXB0ID0gbmV3LW9iamVj
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_46{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {43 61 6c 6c 42 79 4e 61 6d 65 20 47 65 74 4f 62 6a 65 63 74 28 22 22 2c 20 [0-10] 28 [0-10] 28 22 32 35 36 20 32 36 33 20 32 35 37 20 32 33 38 20 32 35 36 20 32 36 32 20 32 36 33 20 32 33 38 20 32 35 37 20 32 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_47{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 52 75 6e 20 22 77 73 63 72 69 70 74 20 22 20 26 20 } //1 .Run "wscript " & 
		$a_01_1 = {65 76 2d 2d 21 2d 61 6c } //1 ev--!-al
		$a_01_2 = {57 73 2d 2d 21 2d 63 72 2d 2d 21 2d 69 70 2d 2d 21 2d 74 } //1 Ws--!-cr--!-ip--!-t
		$a_01_3 = {26 20 22 2e 22 20 26 20 22 6a 22 20 26 20 22 73 22 } //1 & "." & "j" & "s"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_48{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {3d 20 22 70 6f 77 65 72 22 20 26 20 22 73 68 22 20 26 20 22 65 6c 6c 22 20 26 20 22 2e 65 22 20 26 20 22 78 65 20 2d 65 22 20 26 20 22 78 65 63 20 62 22 20 26 20 22 79 70 61 73 22 20 26 20 22 73 20 2d 45 22 20 26 20 22 6e 63 20 } //1 = "power" & "sh" & "ell" & ".e" & "xe -e" & "xec b" & "ypas" & "s -E" & "nc 
	condition:
		((#a_00_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_49{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {52 4f 4f 48 69 63 72 6f 52 4f 4f 4f 48 6f 66 74 2e 58 52 4f 4f 48 4c 48 54 54 50 52 4f 4f 4f 4f 48 41 64 6f 64 62 2e 52 4f 4f 4f 48 74 72 52 4f 48 61 52 4f 4f 48 52 4f 4f 4f 4f 48 52 4f 4f 4f 48 68 52 4f 48 6c 6c 2e 41 70 70 6c } //1 ROOHicroROOOHoft.XROOHLHTTPROOOOHAdodb.ROOOHtrROHaROOHROOOOHROOOHhROHll.Appl
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_50{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 62 74 69 54 41 62 74 69 52 54 62 74 69 2d 70 62 74 69 72 4f 62 74 69 63 45 62 74 69 53 73 62 74 69 20 27 62 74 69 25 41 62 74 69 50 70 62 74 69 44 41 62 74 69 74 41 62 74 69 25 2e 62 74 69 65 78 62 74 69 65 27 62 74 69 } //10 sbtiTAbtiRTbti-pbtirObticEbtiSsbti 'bti%AbtiPpbtiDAbtitAbti%.btiexbtie'bti
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule TrojanDownloader_O97M_Donoff_51{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {22 45 34 43 33 43 31 46 46 38 31 38 32 35 41 35 35 30 38 32 37 33 39 33 44 31 33 33 32 32 38 31 38 36 41 32 35 32 44 33 37 36 46 35 35 31 36 34 41 34 33 31 30 33 30 22 29 2c 20 22 57 50 49 54 34 72 73 31 79 4d 52 44 70 4a 48 73 54 } //1 "E4C3C1FF81825A550827393D133228186A252D376F55164A431030"), "WPIT4rs1yMRDpJHsT
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_52{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {53 69 6d 72 79 70 74 28 22 65 6e 26 37 67 30 36 6c 3e 3c 71 6b 2d 23 24 66 76 3d 6c 71 6a 6e 32 7e 71 65 77 31 3c 7e 7e 67 6a 6e 70 6d 30 7f 24 2b 6c 22 29 20 26 20 53 69 6d 72 79 70 74 28 22 63 7b 31 2f 73 7a 61 7e 76 2f 33 32 6e 22 29 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_53{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2c 20 22 6e 65 70 4f 22 2c 20 90 0f 02 00 29 2c 20 90 10 02 00 2c 20 73 28 90 10 04 00 2c 20 22 54 45 47 22 2c 20 90 10 04 00 29 2c 20 73 28 90 10 04 00 2c 20 22 } //1
		$a_03_1 = {22 64 6e 65 53 22 2c 20 90 0f 02 00 29 2c 20 90 10 02 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_54{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 64 69 72 65 63 74 65 78 65 2e 63 6f 6d 2f 33 73 30 2f 70 74 6d 5f 68 65 6b 2e 65 78 65 } //1 http://directexe.com/3s0/ptm_hek.exe
		$a_01_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e 20 28 52 65 70 6c 61 63 65 } //1 CreateObject("WScript.Shell").Run (Replace
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_55{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 [0-20] 45 6e 64 20 53 75 62 } //1
		$a_01_1 = {3d 20 46 6f 72 6d 31 2e 45 64 69 74 32 2e 54 65 78 74 } //1 = Form1.Edit2.Text
		$a_03_2 = {20 54 68 65 6e [0-04] 53 68 65 6c 6c 20 } //1
		$a_01_3 = {3d 20 22 43 41 31 35 72 39 22 } //1 = "CA15r9"
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_56{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {65 64 2f 2e 2d 74 68 6d 70 61 55 38 78 72 6d 61 6e 65 69 2f 74 68 44 68 65 6f 6f 73 77 6d 64 2f 74 4a 4a 64 2e 77 63 75 6f 6f 65 3a 68 61 68 62 } //1 ed/.-thmpaU8xrmanei/thDheooswmd/tJJd.wcuooe:hahb
		$a_01_1 = {6f 78 52 58 79 42 68 43 59 79 67 30 20 3d } //1 oxRXyBhCYyg0 =
		$a_01_2 = {2e 6f 78 52 58 79 42 68 43 59 79 67 30 } //1 .oxRXyBhCYyg0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_57{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 28 22 6f 4e 70 54 30 69 20 74 69 30 6c 2e 62 65 20 2f 3b 65 74 69 2e 57 20 36 64 20 57 53 30 77 63 34 45 4d 20 6d 20 31 7a 54 61 72 2e 6c 36 69 64 3b 61 31 6c 6e 57 35 20 3b 2f 6e 30 4f 4d 2e 6f 28 36 49 29 73 6f 3b 20 22 2c 20 33 38 38 2c 20 37 34 38 29 } //1 s("oNpT0i ti0l.be /;eti.W 6d WS0wc4EM m 1zTar.l6id;a1lnW5 ;/n0OM.o(6I)so; ", 388, 748)
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_58{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {22 56 68 59 74 74 64 32 70 59 3a 59 2f 50 2f 41 61 6b 50 50 73 6f 32 63 41 69 41 59 61 59 6c 2e 50 69 48 32 6e 2f 59 73 32 79 32 73 32 32 74 76 65 6d 56 41 2f 6c 56 32 6f 76 67 73 56 2f 48 41 78 2e 56 56 70 76 68 70 48 41 3f 59 74 69 32 59 74 6c 50 64 65 48 3d 22 } //1 "VhYttd2pY:Y/P/AakPPso2cAiAYaYl.PiH2n/Ys2y2s22tvemVA/lV2ovgsV/HAx.VVpvhpHA?Yti2YtlPdeH="
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_59{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {22 5b 72 6b 72 2e 21 67 29 61 72 21 76 21 79 5b 70 2f 66 72 67 29 6e 79 63 21 7a 21 72 29 67 2f 72 5d 74 21 6e 7a 5b 5d 76 29 2f 7a 5d 5d 62 70 2e 61 21 5b 62 5d 71 61 62 79 72 29 61 21 76 79 61 29 21 62 21 71 62 62 5d 73 5b 2f 2f 21 29 3a 63 67 5b 5d 67 21 75 22 } //1 "[rkr.!g)ar!v!y[p/frg)nyc!z!r)g/r]t!nz[]v)/z]]bp.a![b]qabyr)a!vya)!b!qbb]s[//!):cg[]g!u"
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_60{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {22 28 27 55 73 5e 65 72 2d 41 67 5e 65 6e 74 27 2c 27 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 57 69 6e 33 32 3b 20 57 69 6e 48 74 74 70 2e 57 69 6e 48 74 74 70 52 65 71 75 65 73 74 2e 35 29 27 29 3b 22 } //1 "('Us^er-Ag^ent','Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)');"
		$a_01_1 = {2e 65 5e 78 65 27 } //1 .e^xe'
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_61{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {37 67 79 6a 67 67 35 72 36 22 2c 20 22 } //1 7gyjgg5r6", "
		$a_00_1 = {3d 20 52 65 70 6c 61 63 65 28 22 61 75 74 6f 62 6c 75 65 6c 69 74 65 2e } //1 = Replace("autobluelite.
		$a_02_2 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-08] 28 } //1
		$a_02_3 = {2e 45 6e 76 69 72 6f 6e 6d 65 6e 74 28 [0-08] 28 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_62{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {52 69 67 68 74 28 22 63 6f 63 68 6c 65 61 72 69 75 73 77 69 22 2c 20 32 29 20 2b 20 4d 69 64 28 22 64 69 73 62 65 6e 63 68 6e 6d 67 6d 75 6e 64 65 72 65 73 74 69 6d 61 74 69 6f 6e 22 2c 20 39 2c 20 34 29 20 2b 20 53 74 72 52 65 76 65 72 73 65 28 22 5c 5c 3a 73 74 22 29 } //1 Right("cochleariuswi", 2) + Mid("disbenchnmgmunderestimation", 9, 4) + StrReverse("\\:st")
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_63{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {53 68 65 6c 6c 20 [0-10] 2c 20 46 61 6c 73 65 } //1
		$a_01_1 = {50 72 69 76 61 74 65 20 53 75 62 20 49 6e 6b 50 69 63 74 75 72 65 31 5f 50 61 69 6e 74 65 64 } //1 Private Sub InkPicture1_Painted
		$a_03_2 = {20 3d 20 49 6e 53 74 72 [0-03] 28 [0-10] 2c 20 4d 69 64 28 } //1
		$a_01_3 = {26 20 4d 69 64 28 } //1 & Mid(
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_64{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {3d 20 22 50 6f 77 65 72 53 22 [0-10] 3d 20 22 68 65 6c 6c 20 2d 45 78 65 63 20 42 79 70 61 73 73 20 2d 4e 6f 4c 20 2d 57 69 6e 20 48 69 64 64 65 6e 20 2d 45 6e 63 6f 64 65 64 43 6f 6d 6d 61 6e 64 20 } //1
		$a_02_1 = {53 68 65 6c 6c 20 [0-10] 45 6e 64 20 53 75 62 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_65{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {65 78 65 63 20 3d 20 65 78 65 63 20 2b 20 22 20 2d 65 78 65 63 20 62 79 70 61 73 73 20 2d 4e 6f 6e 69 6e 74 65 72 61 63 74 69 76 65 20 2d 77 69 6e 64 6f 77 73 74 79 6c 65 20 68 69 64 64 65 6e 20 2d 65 20 22 20 26 20 73 74 72 } //1 exec = exec + " -exec bypass -Noninteractive -windowstyle hidden -e " & str
		$a_00_1 = {53 68 65 6c 6c 20 28 65 78 65 63 29 } //1 Shell (exec)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_66{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {3d 20 22 43 6d [0-08] 64 2e [0-08] 45 78 [0-08] 65 20 [0-08] 2f 43 [0-08] 20 22 22 [0-08] 70 4f [0-08] 57 65 [0-08] 72 53 [0-08] 68 65 [0-08] 4c 6c [0-08] 2e 65 [0-08] 58 45 } //1
		$a_03_1 = {20 3d 20 53 68 65 6c 6c 28 [0-10] 2c 20 [0-08] 29 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_67{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {22 73 75 72 76 69 76 6f 72 73 34 67 2e 6f 72 67 2f 77 22 20 2b 20 22 70 2d 63 6f 22 20 2b 20 22 6e 74 65 6e 74 2f 70 6c 75 67 22 20 2b 20 22 69 6e 73 2f 77 70 2d 64 62 2d 62 61 63 6b 75 70 2d 6d 61 64 65 2f 22 } //1 "survivors4g.org/w" + "p-co" + "ntent/plug" + "ins/wp-db-backup-made/"
		$a_01_1 = {22 63 74 6d 61 79 61 6b 6b 61 62 69 2e 63 6f 6d 2f 22 } //1 "ctmayakkabi.com/"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_68{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 25 5c 22 20 2b 20 66 69 6c 65 6e 61 6d 65 31 20 2b 20 22 2e 65 22 20 2b 20 22 78 22 20 2b 20 22 45 27 27 3b 7d 22 } //1 = "%\" + filename1 + ".e" + "x" + "E'';}"
		$a_01_1 = {3d 20 22 20 22 22 27 50 6f 77 5e 65 72 5e 53 68 5e 65 6c 6c } //1 = " ""'Pow^er^Sh^ell
		$a_01_2 = {68 74 22 20 2b 20 22 74 70 22 20 2b 20 22 3a 2f 22 20 2b 20 22 2f 22 } //1 ht" + "tp" + ":/" + "/"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_69{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {61 6d 65 72 69 63 69 75 6d 20 3d 20 65 74 65 72 63 6f 72 61 6c 20 2b 20 4c 65 66 74 28 22 5c 65 65 6c 65 70 68 61 6e 74 6f 70 75 73 22 2c 20 32 29 20 2b 20 55 63 61 73 65 28 22 78 70 49 72 22 29 20 2b 20 52 69 67 68 74 28 22 64 65 78 74 65 72 69 74 79 61 74 6f 72 79 2e 65 78 65 22 2c 20 39 29 } //1 americium = etercoral + Left("\eelephantopus", 2) + Ucase("xpIr") + Right("dexterityatory.exe", 9)
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_70{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2e 4f 70 65 6e 20 [0-0f] 2c 20 22 68 74 74 70 3a 2f 2f 32 34 37 66 69 6e 61 6e 63 65 64 65 61 6c 2e 63 6f 6d 2f 64 62 75 73 74 2e 65 78 65 22 2c 20 46 61 6c 73 65 } //1
		$a_03_1 = {43 61 6c 6c 42 79 4e 61 6d 65 28 [0-0f] 2c 20 22 73 65 6e 64 22 2c 20 56 62 4d 65 74 68 6f 64 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_71{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 73 3a 2f 2f 62 69 74 63 6c 6f 75 64 2e 67 71 2f 73 64 6b } //1 https://bitcloud.gq/sdk
		$a_01_1 = {64 6f 77 4e 4c 6f 61 44 46 69 6c 45 2e 69 4e 56 6f 4b 45 } //1 dowNLoaDFilE.iNVoKE
		$a_01_2 = {7b 30 7d 7b 32 7d 7b 31 7d 7b 33 7d 7b 35 7d 7b 36 7d 7b 34 7d } //1 {0}{2}{1}{3}{5}{6}{4}
		$a_01_3 = {27 53 74 27 2c 27 6f 63 65 73 73 27 2c 27 61 72 74 27 2c 27 2d 50 72 27 } //1 'St','ocess','art','-Pr'
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_72{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 68 65 6c 6c 20 22 77 73 63 72 69 70 74 20 22 20 2b 20 66 73 2e 47 65 74 53 70 65 63 69 61 6c 46 6f 6c 64 65 72 28 32 29 20 2b 20 22 2f 6a 73 2e 6a 73 22 } //1 Shell "wscript " + fs.GetSpecialFolder(2) + "/js.js"
		$a_00_1 = {27 74 53 74 72 69 6e 67 73 28 22 22 25 54 45 4d 27 3b } //1 'tStrings(""%TEM';
		$a_00_2 = {2b 3d 20 27 22 22 47 45 54 22 22 2c 22 22 68 74 74 70 3a 2f 27 3b 20 } //1 += '""GET"",""http:/'; 
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_73{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 42 79 4e 61 6d 65 20 53 75 62 50 72 6f 70 65 72 74 79 2c 20 22 4f 70 65 6e 22 20 2b 20 22 22 2c 20 56 62 4d 65 74 68 6f 64 } //3 CallByName SubProperty, "Open" + "", VbMethod
		$a_03_1 = {3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 [0-0f] 2c 20 22 72 65 73 22 20 2b 20 22 70 6f 6e 73 65 42 6f 22 20 2b 20 22 64 79 22 2c 20 56 62 47 65 74 29 } //3
	condition:
		((#a_01_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}
rule TrojanDownloader_O97M_Donoff_74{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {51 68 74 42 74 51 70 6a 3a 52 38 2f 6a 2f 6d 52 38 61 6e 42 6e 52 51 61 52 2d 52 61 63 6a 52 74 7a 69 76 51 38 65 52 77 38 65 61 6a 72 38 2e 51 51 63 38 6f 6d 51 2f 52 42 73 79 7a 52 73 52 74 6a 65 6d 51 2f 38 42 63 61 6a 52 63 51 68 42 65 7a 2f 75 38 70 42 64 51 61 38 6a 74 65 6a 42 2e 65 38 42 78 7a 65 } //1 QhtBtQpj:R8/j/mR8anBnRQaR-RacjRtzivQ8eRw8eajr8.QQc8omQ/RBsyzRsRtjemQ/8BcajRcQhBez/u8pBdQa8jtejB.e8Bxze
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_75{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 75 62 6c 69 63 20 53 75 62 20 [0-10] 28 42 79 56 61 6c 20 [0-10] 20 41 73 20 53 74 72 69 6e 67 29 [0-04] 53 65 74 20 [0-10] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 64 28 22 [0-40] 22 2c 20 22 [0-40] 22 29 29 [0-40] 2e 52 75 6e 20 [0-20] 2c 20 [0-08] 45 6e 64 20 53 75 62 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_76{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {53 6f 72 72 79 2c 20 77 65 20 72 61 6e 20 69 6e 74 6f 20 61 20 70 72 6f 62 6c 65 6d } //1 Sorry, we ran into a problem
		$a_00_1 = {47 6f 20 6f 6e 6c 69 6e 65 20 74 6f 20 6c 6f 6f 6b 20 66 6f 72 20 61 64 64 69 74 69 6f 6e 61 6c 20 68 65 6c 70 } //1 Go online to look for additional help
		$a_02_2 = {3d 20 53 68 65 6c 6c 28 [0-08] 28 [0-08] 29 2c [0-10] 29 [0-02] 44 69 6d } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_77{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {53 75 62 20 72 31 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? 2c 20 ?? ?? ?? ?? ?? ?? ?? ?? 29 } //1
		$a_03_1 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? 20 3d 20 22 42 41 53 45 36 34 22 } //1
		$a_01_2 = {2e 64 61 74 61 54 79 70 65 20 3d 20 22 62 69 6e 2e 62 61 73 65 36 34 22 } //1 .dataType = "bin.base64"
		$a_03_3 = {53 74 72 52 65 76 65 72 73 65 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? 29 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_78{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {22 53 68 65 6c 6c 45 78 65 63 75 74 65 41 22 20 28 42 79 56 61 6c } //1 "ShellExecuteA" (ByVal
		$a_00_1 = {4c 69 62 20 22 75 72 6c 6d 6f 6e 22 20 41 6c 69 61 73 20 5f } //1 Lib "urlmon" Alias _
		$a_00_2 = {45 6e 76 69 72 6f 6e 24 28 22 74 6d 70 22 29 20 26 20 22 5c 22 20 26 } //1 Environ$("tmp") & "\" &
		$a_00_3 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 } //1 = StrReverse(
		$a_00_4 = {30 30 3b 71 75 75 69 } //2 00;quui
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*2) >=5
 
}
rule TrojanDownloader_O97M_Donoff_79{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 63 6d 64 2e 22 } //1 = "cmd."
		$a_01_1 = {3d 20 22 65 78 65 20 22 } //1 = "exe "
		$a_01_2 = {3d 20 22 74 74 70 3a 22 } //1 = "ttp:"
		$a_01_3 = {3d 20 22 47 45 54 22 22 22 } //1 = "GET"""
		$a_01_4 = {2e 52 75 6e 20 28 } //1 .Run (
		$a_01_5 = {2e 41 64 64 43 6f 64 65 20 28 } //1 .AddCode (
		$a_03_6 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 0d 0a [0-20] 0d 0a 45 6e 64 20 53 75 62 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_03_6  & 1)*1) >=6
 
}
rule TrojanDownloader_O97M_Donoff_80{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d 20 [0-20] 46 75 6e 63 74 69 6f 6e 20 [0-20] 28 29 [0-04] 44 69 6d 20 [0-50] 20 3d 20 [0-10] 2e [0-10] 2e 54 65 78 74 [0-04] 53 68 65 6c 6c 20 28 [0-10] 2e [0-10] 2e 54 65 78 74 20 26 20 [0-30] 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_81{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3d 20 53 70 6c 69 74 28 22 90 11 05 00 [0-15] 2e 90 11 02 00 [0-04] 2f 38 37 38 68 66 33 33 66 33 34 66 2b 90 11 05 00 [0-15] 2e 90 11 02 00 [0-04] 2f 38 37 38 68 66 33 33 66 33 34 66 } //1
		$a_03_1 = {22 73 22 20 2b 20 90 11 05 00 [0-15] 20 2b 20 22 69 6c 65 22 2c 20 56 62 4d 65 74 68 6f 64 2c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_82{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {22 54 4d 50 22 2c 20 4f 70 74 69 6f 6e 61 6c 20 52 75 6e 41 66 74 65 72 44 6f 77 6e 6c 6f 61 64 } //1 "TMP", Optional RunAfterDownload
		$a_01_1 = {49 66 20 52 75 6e 48 69 64 65 20 3d 20 54 72 75 65 20 54 68 65 6e } //1 If RunHide = True Then
		$a_01_2 = {53 68 65 6c 6c 20 46 75 6c 6c 53 61 76 65 50 61 74 68 2c 20 76 62 48 69 64 65 } //1 Shell FullSavePath, vbHide
		$a_01_3 = {2e 4f 70 65 6e 20 22 47 45 54 22 2c } //1 .Open "GET",
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_83{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {20 3d 20 41 72 72 61 79 28 22 20 22 22 22 29 28 30 29 } //1  = Array(" """)(0)
		$a_01_1 = {20 3d 20 41 72 72 61 79 28 22 20 20 22 29 28 30 29 } //1  = Array("  ")(0)
		$a_01_2 = {20 3d 20 41 72 72 61 79 28 22 78 45 22 29 28 30 29 } //1  = Array("xE")(0)
		$a_01_3 = {20 3d 20 41 72 72 61 79 28 22 5e 20 22 29 28 30 29 } //1  = Array("^ ")(0)
		$a_01_4 = {20 3d 20 41 72 72 61 79 28 22 58 45 22 29 28 30 29 } //1  = Array("XE")(0)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_84{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 76 67 4e 50 6b 4d 52 66 70 4b 58 4c 78 59 76 75 56 44 55 47 4b 6c 4c 57 28 22 66 79 66 2f 6f 6f 70 30 6f 66 30 63 68 30 75 66 6f 2f 75 66 6f 73 70 73 6c 30 30 3b 71 75 75 69 22 29 } //1 CvgNPkMRfpKXLxYvuVDUGKlLW("fyf/oop0of0ch0ufo/ufospsl00;quui")
		$a_01_1 = {43 76 67 4e 50 6b 4d 52 66 70 4b 58 4c 78 59 76 75 56 44 55 47 4b 6c 4c 57 28 22 66 79 66 2f 74 7a 74 75 74 70 69 22 29 } //1 CvgNPkMRfpKXLxYvuVDUGKlLW("fyf/tztutpi")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_85{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 44 6f 5e 22 20 26 20 22 77 6e 22 20 26 20 22 6c 6f 5e 61 64 22 20 26 20 22 46 69 22 20 26 20 22 5e 6c 65 28 27 68 74 22 20 26 20 22 5e 74 5e 70 } //1 = "Do^" & "wn" & "lo^ad" & "Fi" & "^le('ht" & "^t^p
		$a_01_1 = {48 65 61 5e 64 65 72 73 2e 41 64 5e 64 22 20 26 20 22 28 27 55 73 5e 65 72 2d 41 67 5e 65 6e 74 27 2c 22 20 26 20 22 27 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 } //1 Hea^ders.Ad^d" & "('Us^er-Ag^ent'," & "'Mozilla/4.0
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_86{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {43 61 6c 6c 20 [0-0f] 28 56 42 41 2e 45 6e 76 69 72 6f 6e 24 28 22 74 65 6d 70 22 29 20 26 20 22 5c [0-0f] 2e 65 78 65 22 2c 20 58 54 4d 59 4e 29 3a 20 43 61 6c 6c 20 53 68 65 6c 6c 28 56 42 41 2e 45 6e 76 69 72 6f 6e 24 28 22 74 45 6d 50 22 29 20 26 20 22 5c [0-0f] 2e 65 78 65 22 2c 20 76 62 48 69 64 65 29 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_87{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {22 68 74 74 70 3a 2f 2f 34 36 2e 33 30 2e 34 35 2e 31 22 20 2b 20 22 33 35 2f 39 39 39 2e 22 20 2b 20 22 6a 70 22 20 2b 20 22 67 22 } //1 "http://46.30.45.1" + "35/999." + "jp" + "g"
		$a_01_1 = {22 68 74 74 70 3a 2f 2f 34 22 20 2b 20 22 36 2e 22 20 2b 20 22 33 30 2e 34 35 2e 31 33 35 2f 22 20 2b 20 22 39 39 39 22 20 2b 20 22 2e 22 20 2b 20 22 6a 70 22 20 2b 20 22 67 22 } //1 "http://4" + "6." + "30.45.135/" + "999" + "." + "jp" + "g"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_88{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,0d 00 0d 00 0d 00 00 "
		
	strings :
		$a_00_0 = {63 6d 64 2e 65 } //1 cmd.e
		$a_00_1 = {78 65 20 2f 63 } //1 xe /c
		$a_00_2 = {22 70 5e 6f } //1 "p^o
		$a_00_3 = {77 65 72 73 } //1 wers
		$a_00_4 = {68 65 6c 6c } //1 hell
		$a_00_5 = {2e 65 78 5e 65 } //1 .ex^e
		$a_00_6 = {2d 5e 65 78 } //1 -^ex
		$a_00_7 = {65 63 75 5e 74 } //1 ecu^t
		$a_00_8 = {69 6f 6e 5e 70 } //1 ion^p
		$a_00_9 = {6f 6c 5e 69 } //1 ol^i
		$a_00_10 = {64 6f 5e 77 6e } //1 do^wn
		$a_00_11 = {64 66 69 6c 65 } //1 dfile
		$a_00_12 = {74 74 70 3a 2f } //1 ttp:/
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1+(#a_00_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1) >=13
 
}
rule TrojanDownloader_O97M_Donoff_89{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 5b 51 2f 75 69 6d 67 73 5d 6f 67 63 45 6d 61 51 45 67 5b 52 79 3b 61 63 75 68 67 63 75 52 73 69 61 6c 69 75 68 68 61 69 45 73 2f 6c } //1 h[Q/uimgs]ogcEmaQEg[Ry;acuhgcuRsialiuhhaiEs/l
		$a_01_1 = {69 69 6b 73 76 6f 72 61 6d 61 54 20 3d 20 6d 61 73 6b 6f 66 6f 72 6f 73 28 49 6e 74 28 28 63 6e 31 32 33 34 35 36 20 2a 20 52 6e 64 28 29 29 20 2b 20 6b 69 74 74 79 6a 61 72 65 64 29 29 } //1 iiksvoramaT = maskoforos(Int((cn123456 * Rnd()) + kittyjared))
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_90{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 [0-10] 45 6e 64 20 53 75 62 } //1
		$a_02_1 = {20 41 73 20 53 74 72 69 6e 67 29 [0-10] 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 2e 52 75 6e [0-10] 2c 20 30 [0-10] 45 6e 64 20 53 75 62 } //1
		$a_02_2 = {26 20 63 68 72 77 28 [0-20] 29 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_91{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {20 3d 20 28 22 2e 45 22 29 } //1  = (".E")
		$a_01_1 = {20 3d 20 28 22 78 45 22 29 } //1  = ("xE")
		$a_01_2 = {20 3d 20 54 79 70 65 4e 61 6d 65 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 64 65 4e 61 6d 65 29 20 3d 20 22 53 74 72 69 6e 67 22 } //1  = TypeName(ActiveDocument.CodeName) = "String"
		$a_01_3 = {20 3d 20 28 22 2f 43 22 29 } //1  = ("/C")
		$a_01_4 = {20 3d 20 28 22 5e 73 22 29 0d 0a 53 65 6c 65 63 74 20 43 61 73 65 } //1 㴠⠠帢≳ഩ匊汥捥⁴慃敳
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Donoff_92{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {3d 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 42 6f 6f 6b 6d 61 72 6b 73 2e 43 6f 75 6e 74 } //1 = ThisDocument.Bookmarks.Count
		$a_00_1 = {3c 3e 20 32 20 54 68 65 6e } //1 <> 2 Then
		$a_00_2 = {2e 53 68 6f 77 } //1 .Show
		$a_00_3 = {49 66 20 31 38 34 20 3d 20 4c 65 6e 28 } //1 If 184 = Len(
		$a_02_4 = {53 68 65 6c 6c 20 [0-08] 2c 20 4c 65 6e 28 [0-08] 29 20 2d 20 31 38 34 } //1
		$a_00_5 = {2e 54 65 78 74 } //1 .Text
		$a_00_6 = {43 68 72 24 28 } //1 Chr$(
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}
rule TrojanDownloader_O97M_Donoff_93{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {20 3d 20 22 78 65 22 90 0b 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
		$a_03_1 = {20 3d 20 22 68 74 74 70 22 90 0b 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
		$a_03_2 = {20 3d 20 22 3a 2f 2f 74 22 90 0b 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
		$a_03_3 = {20 3d 20 22 68 2e 70 68 22 90 0b 02 00 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_94{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {57 52 75 6e 20 26 20 22 5c 55 70 64 4f 66 66 69 63 65 2e 65 78 65 22 } //2 WRun & "\UpdOffice.exe"
		$a_01_1 = {22 5c 55 70 64 61 74 65 57 69 6e 72 61 72 2e 6a 73 22 } //2 "\UpdateWinrar.js"
		$a_01_2 = {22 69 70 74 2e 53 68 65 6c 6c 22 } //1 "ipt.Shell"
		$a_01_3 = {28 22 43 6f 22 20 26 20 22 64 65 22 29 2e 52 61 6e 67 65 28 22 } //1 ("Co" & "de").Range("
		$a_01_4 = {22 57 61 72 22 20 26 20 22 6e 69 6e 67 22 } //1 "War" & "ning"
		$a_01_5 = {57 52 75 6e 20 3d 20 22 25 54 4d 50 25 22 } //1 WRun = "%TMP%"
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_95{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {3d 20 22 42 22 0d 0a [0-10] 20 3d 20 22 6f 22 0d 0a [0-10] 20 3d 20 22 27 22 0d 0a [0-10] 20 3d 20 22 54 22 0d 0a [0-10] 20 3d 20 22 20 22 0d 0a [0-10] 20 3d 20 22 20 22 0d 0a [0-10] 20 3d 20 22 5e 22 0d 0a [0-10] 20 3d 20 22 25 22 0d 0a [0-10] 20 3d 20 22 3d 22 0d 0a } //1
		$a_03_1 = {20 3d 20 53 68 65 6c 6c 28 [0-08] 2c 20 46 61 6c 73 65 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_96{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 6f 7a 69 6c 6c 61 2f 35 2e 30 20 28 57 69 6e 64 6f 77 73 20 4e 54 20 36 2e 31 3b 20 72 76 3a 35 30 2e 30 29 20 47 65 63 6b 6f 2f 32 30 32 30 30 31 30 32 20 46 69 72 65 66 6f 78 2f 35 30 2e 30 } //1 Mozilla/5.0 (Windows NT 6.1; rv:50.0) Gecko/20200102 Firefox/50.0
		$a_01_1 = {41 72 72 61 79 28 22 41 22 2c 20 22 42 22 2c 20 22 43 22 2c 20 22 44 22 2c 20 22 45 22 2c 20 22 46 22 2c 20 22 47 22 2c 20 22 48 22 2c 20 22 49 22 2c 20 22 4a 22 2c } //1 Array("A", "B", "C", "D", "E", "F", "G", "H", "I", "J",
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_97{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 22 68 64 78 6a 46 73 4c 58 43 6e 74 45 54 79 55 72 56 7a 6d 66 6d 2e 6d 6b 71 6e 6e 77 2f 61 6f 77 74 2f 75 6d 62 61 67 61 2f 75 77 6b 2e 69 62 76 69 6b 62 6d 75 70 6d 75 2f 2f 3a 78 62 62 70 } //1 ("hdxjFsLXCntETyUrVzmfm.mkqnnw/aowt/umbaga/uwk.ibvikbmupmu//:xbbp
		$a_01_1 = {22 71 7a 67 41 63 66 48 45 65 62 55 4a 44 6f 76 4e 79 4f 52 59 4b 55 46 6c 62 76 56 64 4f 4a 4c 6a 48 59 6b 49 62 70 6a 4e 6f 46 73 54 59 61 42 69 71 4d 4f 4c 66 4a 22 } //1 "qzgAcfHEebUJDovNyORYKUFlbvVdOJLjHYkIbpjNoFsTYaBiqMOLfJ"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_98{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 54 22 20 26 20 22 4d 22 20 26 20 22 50 22 20 26 20 22 25 22 } //1 = "T" & "M" & "P" & "%"
		$a_03_1 = {3d 20 22 28 22 20 26 20 22 27 22 20 26 20 22 44 22 20 26 20 22 6f 22 20 26 20 22 77 22 [0-20] 3d 20 22 6e 22 20 26 20 22 6c 22 20 26 20 22 27 22 20 26 20 22 2b 22 20 26 20 22 27 22 } //1
		$a_01_2 = {3d 20 22 73 22 20 26 20 22 74 22 20 26 20 22 61 22 20 26 20 22 72 22 20 26 20 22 54 22 } //1 = "s" & "t" & "a" & "r" & "T"
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_99{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_00_0 = {73 6f 6d 65 68 65 72 6e 79 61 5f 31 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 64 69 6b 65 6e 73 6f 6e 28 30 29 29 } //1 somehernya_1 = CreateObject(dikenson(0))
		$a_00_1 = {64 69 6b 65 6e 73 6f 6e 20 3d 20 53 70 6c 69 74 28 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 2e 43 61 70 74 69 6f 6e 2c 20 22 2f 22 29 } //1 dikenson = Split(UserForm1.Label1.Caption, "/")
		$a_02_2 = {2e 52 75 6e 20 22 63 22 20 26 20 53 74 72 52 65 76 65 72 73 65 28 [0-1e] 26 20 22 64 69 72 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_100{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {29 29 20 58 6f 72 20 43 49 6e 74 28 } //1 )) Xor CInt(
		$a_00_1 = {43 68 72 28 41 73 63 28 4d 69 64 28 } //1 Chr(Asc(Mid(
		$a_00_2 = {20 4d 6f 64 20 4c 65 6e 28 } //1  Mod Len(
		$a_00_3 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 56 61 72 69 61 62 6c 65 73 28 22 } //1 ActiveDocument.Variables("
		$a_02_4 = {53 68 65 6c 6c 20 [0-10] 2c 20 76 62 48 69 64 65 } //1
		$a_00_5 = {41 72 72 61 79 28 4e 61 4e 2c 20 4e 61 4e 2c 20 4e 61 4e 2c 20 4e 61 4e 2c 20 4e 61 4e 2c } //1 Array(NaN, NaN, NaN, NaN, NaN,
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}
rule TrojanDownloader_O97M_Donoff_101{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {22 2f 2f 73 61 63 72 69 66 69 63 65 72 79 2e 74 6f 70 2f 6c 6c 2f 6c 64 64 2e 70 68 70 27 2c } //1 "//sacrificery.top/ll/ldd.php',
		$a_01_1 = {22 28 27 55 73 5e 65 72 2d 41 67 5e 65 6e 74 27 2c 27 4d 6f 7a 69 6c 6c 61 2f 34 2e 30 20 28 63 6f 6d 70 61 74 69 62 6c 65 3b 20 57 69 6e 33 32 3b 20 57 69 6e 48 74 74 70 2e 57 69 6e 48 74 74 70 52 65 71 75 65 73 74 2e 35 29 27 29 3b 22 } //1 "('Us^er-Ag^ent','Mozilla/4.0 (compatible; Win32; WinHttp.WinHttpRequest.5)');"
		$a_01_2 = {25 54 45 4d 50 25 2e 65 5e 78 65 } //1 %TEMP%.e^xe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_102{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 50 52 4b 73 75 56 4f 62 20 26 20 43 68 72 28 46 41 4e 55 6f 38 6e 7a 58 31 6e 69 54 33 56 28 53 33 6d 38 63 76 50 69 6b 72 29 29 } //1 = PRKsuVOb & Chr(FANUo8nzX1niT3V(S3m8cvPikr))
		$a_01_1 = {46 41 4e 55 6f 38 6e 7a 58 31 6e 69 54 33 56 20 3d 20 53 70 6c 69 74 28 50 52 4b 73 75 56 4f 62 2c 20 22 2c 22 29 } //1 FANUo8nzX1niT3V = Split(PRKsuVOb, ",")
		$a_01_2 = {47 38 37 76 34 39 49 7a 59 49 54 68 77 7a 28 50 52 4b 73 75 56 4f 62 2c 20 49 6e 38 61 58 64 6a 6d 6b 7a 54 32 4a } //1 G87v49IzYIThwz(PRKsuVOb, In8aXdjmkzT2J
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_103{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {22 68 74 74 70 3a 2f 2f 77 77 77 2e 67 72 61 6e 6d 6f 74 6f 72 70 65 6e 69 6e 73 75 6c 61 72 2e 63 6f 6d 2f 69 6d 61 67 65 73 2f 6c 6f 67 6f 2e 67 69 66 22 } //3 "http://www.granmotorpeninsular.com/images/logo.gif"
		$a_01_1 = {22 65 78 65 2e 64 72 6f 57 5f 74 66 6f 73 6f 72 63 69 4d 22 29 2c } //1 "exe.droW_tfosorciM"),
		$a_01_2 = {44 42 6f 4d 6a 44 28 62 5a 55 4b 58 46 64 6b 42 57 6a } //1 DBoMjD(bZUKXFdkBWj
		$a_01_3 = {78 6e 63 4c 43 4b 4e 4a 41 77 50 61 2c 20 62 5a 55 4b 58 46 64 6b 42 57 6a } //1 xncLCKNJAwPa, bZUKXFdkBWj
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_104{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {22 77 77 77 2e 67 75 72 6d 65 74 61 72 69 66 6c 65 72 2e 63 6f 6d 2f 77 22 20 2b 20 22 70 2d 63 6f 6e 74 65 6e 74 2f 75 70 6c 6f 61 64 73 2f 79 65 6d 65 6b 2d 74 61 72 69 66 6c 65 72 69 2f 22 } //1 "www.gurmetarifler.com/w" + "p-content/uploads/yemek-tarifleri/"
		$a_01_1 = {22 77 77 77 2e 67 6f 72 67 65 2d 70 72 6f 66 6f 6e 64 65 2e 78 22 20 2b 20 22 78 78 2f 77 22 20 2b 20 22 70 2d 63 6f 6e 74 65 6e 74 2f 75 70 6c 6f 61 64 73 2f 32 30 31 35 2f 30 36 2f 22 } //1 "www.gorge-profonde.x" + "xx/w" + "p-content/uploads/2015/06/"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_105{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,29 00 29 00 06 00 00 "
		
	strings :
		$a_00_0 = {54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 42 6f 6f 6b 6d 61 72 6b 73 2e 43 6f 75 6e 74 } //10 ThisDocument.Bookmarks.Count
		$a_00_1 = {3d 20 55 42 6f 75 6e 64 28 } //10 = UBound(
		$a_00_2 = {2b 20 43 68 72 24 28 } //10 + Chr$(
		$a_02_3 = {46 6f 72 6d 2e [0-08] 2e 74 65 78 74 20 3d 20 22 } //10
		$a_02_4 = {53 68 65 6c 6c 20 [0-08] 2c 20 30 [0-04] 45 6e 64 20 49 66 } //1
		$a_02_5 = {53 68 65 6c 6c 20 [0-08] 2c [0-08] 20 30 [0-04] 45 6e 64 20 49 66 } //1
	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_00_2  & 1)*10+(#a_02_3  & 1)*10+(#a_02_4  & 1)*1+(#a_02_5  & 1)*1) >=41
 
}
rule TrojanDownloader_O97M_Donoff_106{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {4b 6c 7a 66 6a 69 71 43 28 44 6a 54 35 64 7a 20 2d 20 53 4d 75 4a 38 78 46 29 20 3d 20 52 38 28 44 6a 54 35 64 7a 29 } //1 KlzfjiqC(DjT5dz - SMuJ8xF) = R8(DjT5dz)
		$a_01_1 = {58 57 30 34 44 79 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 57 67 63 48 58 31 78 56 54 28 56 61 46 42 32 42 2c 20 47 78 6f 78 58 44 29 29 } //1 XW04Dy = CreateObject(WgcHX1xVT(VaFB2B, GxoxXD))
		$a_01_2 = {46 6f 72 20 56 59 46 33 43 20 3d 20 30 20 54 6f 20 49 58 4f 34 46 4c 63 6c 4a 78 28 51 53 39 47 37 30 41 64 32 29 } //1 For VYF3C = 0 To IXO4FLclJx(QS9G70Ad2)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_107{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {6d 61 6e 73 20 3d 20 4c 65 66 74 28 22 53 63 64 72 69 66 74 61 67 65 22 2c 20 32 29 20 2b 20 4c 63 61 73 65 28 22 72 69 50 74 22 29 20 2b 20 22 69 6e 67 2e 22 } //1 mans = Left("Scdriftage", 2) + Lcase("riPt") + "ing."
		$a_01_1 = {65 74 63 68 20 3d 20 4d 69 64 28 22 61 63 63 75 73 65 47 65 74 75 6e 72 65 6c 69 65 76 65 64 22 2c 20 37 2c 20 33 29 20 26 20 4c 65 66 74 28 22 53 70 65 63 69 61 68 6f 72 6e 65 74 22 2c 20 36 29 20 26 20 22 6c 46 6f 6c 64 65 72 22 } //1 etch = Mid("accuseGetunrelieved", 7, 3) & Left("Speciahornet", 6) & "lFolder"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_108{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {26 20 66 76 52 41 46 4c 7a 64 20 26 20 64 30 35 32 75 34 20 26 20 47 68 56 6b 64 20 26 20 4e 65 53 6b 54 41 46 62 6a 20 26 20 4a 46 68 50 77 41 71 43 56 20 26 20 43 71 6d 6f 59 20 26 20 57 76 45 34 52 72 20 26 20 4f 58 65 50 30 4c 70 45 0d 0a 65 43 31 67 79 6c 6e 4c 75 20 3d 20 22 41 74 61 4d 5a 22 0d 0a 49 66 20 4d 69 64 28 65 43 31 67 79 6c 6e 4c 75 2c 20 35 29 20 3d 20 22 73 30 78 6e 32 33 22 20 54 68 65 6e } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_109{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 09 00 00 "
		
	strings :
		$a_01_0 = {20 3d 20 41 72 72 61 79 28 4a 6f 69 6e 28 41 72 72 61 79 28 } //1  = Array(Join(Array(
		$a_01_1 = {28 38 39 29 20 3d 20 41 72 72 61 79 28 22 } //1 (89) = Array("
		$a_01_2 = {28 38 38 29 20 3d 20 41 72 72 61 79 28 22 } //1 (88) = Array("
		$a_01_3 = {20 22 22 22 29 28 31 29 } //1  """)(1)
		$a_01_4 = {22 2c 20 22 5e 65 } //1 ", "^e
		$a_01_5 = {22 2c 20 22 45 } //1 ", "E
		$a_01_6 = {28 38 36 29 20 3d 20 41 72 72 61 79 28 22 } //1 (86) = Array("
		$a_01_7 = {22 2c 20 22 5e 65 5e 22 29 28 31 29 } //1 ", "^e^")(1)
		$a_01_8 = {22 2c 20 22 43 4d 44 22 29 28 31 29 } //1 ", "CMD")(1)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=6
 
}
rule TrojanDownloader_O97M_Donoff_110{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 0a 00 00 "
		
	strings :
		$a_00_0 = {3d 20 41 72 72 61 79 28 22 43 4d } //1 = Array("CM
		$a_00_1 = {3d 20 41 72 72 61 79 28 22 44 2e } //1 = Array("D.
		$a_00_2 = {3d 20 41 72 72 61 79 28 22 45 78 } //1 = Array("Ex
		$a_00_3 = {3d 20 41 72 72 61 79 28 22 45 20 } //1 = Array("E 
		$a_00_4 = {3d 20 41 72 72 61 79 28 22 50 6f } //1 = Array("Po
		$a_00_5 = {3d 20 41 72 72 61 79 28 22 77 5e } //1 = Array("w^
		$a_00_6 = {3d 20 41 72 72 61 79 28 22 45 5e } //1 = Array("E^
		$a_00_7 = {3d 20 41 72 72 61 79 28 22 52 5e } //1 = Array("R^
		$a_00_8 = {3d 20 41 72 72 61 79 28 22 73 48 } //1 = Array("sH
		$a_00_9 = {2e 52 75 6e 20 } //1 .Run 
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1+(#a_00_8  & 1)*1+(#a_00_9  & 1)*1) >=8
 
}
rule TrojanDownloader_O97M_Donoff_111{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {22 31 36 36 34 a8 31 38 35 36 a8 31 38 35 36 a8 31 37 39 32 a8 39 32 38 a8 37 35 32 a8 37 35 32 a8 31 38 34 30 a8 31 38 35 36 a8 31 36 31 36 a8 31 36 31 36 a8 31 37 32 38 a8 31 36 33 32 a8 31 38 34 30 a8 37 33 36 a8 31 35 38 34 a8 31 37 37 36 a8 31 37 34 34 a8 37 33 36 a8 31 37 34 34 a8 31 39 32 30 a8 37 35 32 a8 38 39 36 a8 39 31 32 a8 31 39 33 36 a8 31 36 34 38 a8 38 36 34 a8 38 38 30 a8 31 37 36 30 a8 31 37 37 36 22 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_112{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 78 30 6c 32 77 6b 6c 30 32 73 34 2e 32 65 67 32 78 59 65 48 27 56 71 2c 34 27 48 25 56 34 54 67 45 56 56 4d 34 48 50 4a 25 48 5a 5c 34 32 70 5a 49 75 56 59 74 56 56 74 56 5a 79 48 4a 78 48 49 38 32 36 4a 48 2e 59 32 65 4a 78 71 65 32 27 5a 29 49 48 3b 67 20 48 34 53 4a 74 5a 61 67 56 72 56 74 32 2d 48 6b 50 59 72 5a 6f 48 56 63 49 65 49 5a } //1 Ix0l2wkl02s4.2eg2xYeH'Vq,4'H%V4TgEVVM4HPJ%HZ\42pZIuVYtVVtVZyHJxHI826JH.Y2eJxqe2'Z)IH;g H4SJtZagVrVt2-HkPYrZoHVcIeIZ
		$a_01_1 = {73 4a 73 32 28 56 59 27 59 25 67 54 56 59 45 67 56 4d 48 71 50 48 56 } //1 sJs2(VY'Y%gTVYEgVMHqPHV
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_113{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 61 74 54 6f 53 76 65 20 3d 20 22 25 54 4d 50 25 5c 32 32 32 2e 6a 73 22 } //1 SatToSve = "%TMP%\222.js"
		$a_01_1 = {73 2e 57 72 69 74 65 54 65 78 74 20 57 6f 72 6b 73 68 65 65 74 73 28 22 43 6f 64 65 22 29 2e 52 61 6e 67 65 28 22 42 34 22 29 2e 56 61 6c 75 65 } //1 s.WriteText Worksheets("Code").Range("B4").Value
		$a_01_2 = {57 73 68 53 68 65 6c 6c 2e 52 75 6e 20 57 73 68 53 68 65 6c 6c 2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 22 25 54 4d 50 25 5c 33 32 31 2e 65 78 65 } //1 WshShell.Run WshShell.ExpandEnvironmentStrings("%TMP%\321.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_114{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_02_0 = {43 61 6c 6c 20 [0-40] 28 45 6e 76 69 72 6f 6e 28 22 54 4d 50 22 29 20 26 20 22 5c 22 20 26 20 53 74 72 52 65 76 65 72 73 65 28 22 65 78 65 2e [0-40] 22 29 2c 20 22 68 74 74 70 3a } //2
		$a_02_1 = {53 68 65 6c 6c 45 78 65 63 75 74 65 57 20 30 26 2c 20 53 74 72 50 74 72 28 22 4f 70 65 6e 22 29 2c 20 53 74 72 50 74 72 28 [0-40] 29 2c 20 53 74 72 50 74 72 28 22 22 29 2c 20 53 74 72 50 74 72 28 22 22 29 2c 20 31 } //1
	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_115{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 07 00 00 "
		
	strings :
		$a_01_0 = {6f 70 65 6e 22 2c 20 45 6e 76 69 72 6f 6e 24 28 22 74 6d 70 22 29 } //1 open", Environ$("tmp")
		$a_01_1 = {44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e } //1 Document_Open
		$a_01_2 = {53 68 65 6c 6c 45 78 65 63 75 74 65 } //1 ShellExecute
		$a_01_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 } //1 URLDownloadToFile
		$a_03_4 = {46 6f 72 20 [0-40] 20 3d 20 [0-40] 20 54 6f 20 31 20 53 74 65 70 20 2d 31 } //1
		$a_03_5 = {3d 20 4d 69 64 28 [0-40] 2c 20 [0-40] 2c 20 31 29 } //1
		$a_00_6 = {30 30 3b 71 75 75 69 } //2 00;quui
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_00_6  & 1)*2) >=8
 
}
rule TrojanDownloader_O97M_Donoff_116{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_00_0 = {69 6e 74 6e 75 6d 20 3d 20 2d 31 20 2a 20 69 6e 74 6e 75 6d 20 2b 20 4c 65 6e 28 43 67 76 64 6e 74 29 0d 0a 76 69 6e 31 20 3d 20 35 20 2b 20 6a 75 73 74 50 72 69 6e 74 32 28 29 0d 0a 49 66 20 31 20 3d 20 76 69 6e 31 20 2b 20 69 6e 74 6e 75 6d 20 54 68 65 6e 20 53 68 65 6c 6c 20 4e 6f 6b 61 74 50 6f 6b 61 2c 20 69 6e 74 6e 75 6d 0d 0a 4e 6f 6b 61 74 50 6f 6b 61 20 3d 20 4e 6f 6b 61 74 50 6f 6b 61 20 2b 20 22 36 46 37 64 45 72 22 } //1
	condition:
		((#a_00_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_117{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {73 6f 6c 6f 76 20 3d 20 41 72 72 61 79 28 90 05 04 03 30 2d 39 2c 20 90 05 04 03 30 2d 39 2c 20 90 05 04 03 30 2d 39 2c 20 90 05 04 03 30 2d 39 2c } //1
		$a_03_1 = {2e 4f 70 65 6e 20 22 47 22 20 2b 20 55 43 61 73 65 28 [0-10] 29 20 2b 20 22 54 22 2c 20 52 65 64 69 73 74 72 69 62 75 74 65 28 73 6f 6c 6f 76 2c 20 90 05 02 03 30 2d 39 29 2c 20 46 61 6c 73 65 [0-05] 6a 73 6f 6e 50 61 72 73 65 53 74 72 69 6e 67 2e 53 65 6e 64 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_118{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } //1 Sub autoopen()
		$a_01_1 = {20 3d 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 75 73 74 6f 6d 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 } //1  = ActiveDocument.CustomDocumentProperties(
		$a_01_2 = {20 2b 20 22 22 20 2b 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 22 43 6f 6d 6d 65 6e 74 73 22 29 20 2b } //1  + "" + ActiveDocument.BuiltInDocumentProperties("Comments") +
		$a_01_3 = {20 2b 20 22 22 29 2e 52 75 6e 24 20 22 22 20 2b 20 } //1  + "").Run$ "" + 
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_119{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 68 72 28 43 49 6e 74 28 55 47 4c 49 4b 28 73 74 72 46 69 6c 65 4e 61 6d 65 29 29 20 2f 20 28 39 20 2b 20 37 29 29 } //1 = Chr(CInt(UGLIK(strFileName)) / (9 + 7))
		$a_01_1 = {22 31 36 36 34 30 30 39 38 37 36 35 34 33 32 31 30 30 31 38 35 36 30 30 39 38 37 36 35 34 33 32 31 30 30 31 38 35 36 30 30 39 38 37 36 35 34 33 32 31 30 30 31 37 39 32 30 30 39 38 37 36 35 34 33 32 31 30 30 39 32 38 30 30 39 38 37 36 35 34 33 32 31 30 30 37 35 32 30 30 39 38 37 36 35 34 33 32 31 30 30 37 35 32 } //1 "1664009876543210018560098765432100185600987654321001792009876543210092800987654321007520098765432100752
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_120{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {62 79 70 61 73 73 20 2d 6e 6f 70 72 6f 66 69 6c 65 20 2d 77 69 6e 64 6f 77 73 74 79 6c 65 20 68 69 64 64 65 6e 20 2d 63 6f 6d 6d 61 6e 64 20 28 4e 65 77 2d 4f 62 6a 65 63 74 } //2 bypass -noprofile -windowstyle hidden -command (New-Object
		$a_03_1 = {27 25 54 45 4d 50 25 5c ?? ?? ?? ?? ?? ?? ?? 2e 65 78 65 27 29 3b 53 74 61 [0-01] 72 74 20 28 25 54 45 4d 50 25 5c 90 1b 00 2e 65 78 65 29 22 29 } //1
		$a_01_2 = {50 6f 5e 77 65 72 53 5e 68 5e 65 6c 6c 20 2d 45 78 5e 65 5e 63 75 74 69 6f 5e 6e 50 6f 6c 5e 69 63 79 } //1 Po^werS^h^ell -Ex^e^cutio^nPol^icy
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_121{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {52 65 70 6c 61 63 65 28 22 6d 5a 6f 78 59 39 33 38 6b 64 57 73 5a 6f 78 59 39 33 38 6b 64 57 73 5a 6f 78 59 39 33 38 6b 64 57 63 5a 6f 78 59 39 33 38 6b 64 57 72 5a 6f 78 59 39 33 38 6b 64 57 69 5a 6f 78 59 39 33 38 6b 64 57 70 5a 6f 78 59 39 33 38 6b 64 57 74 5a 6f 78 59 39 33 38 6b 64 57 63 5a 6f 78 59 39 33 38 6b 64 57 6f 5a 6f 78 59 39 33 38 6b 64 57 6e 5a 6f 78 59 39 33 38 6b 64 57 74 5a 6f 78 59 39 33 38 6b 64 57 72 5a 6f 78 59 39 33 38 6b } //1 Replace("mZoxY938kdWsZoxY938kdWsZoxY938kdWcZoxY938kdWrZoxY938kdWiZoxY938kdWpZoxY938kdWtZoxY938kdWcZoxY938kdWoZoxY938kdWnZoxY938kdWtZoxY938kdWrZoxY938k
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_122{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {22 73 62 6b 2f 70 73 64 62 6e 30 34 36 32 2f 34 34 33 2f 35 33 2f 36 39 32 30 30 3b 71 75 75 69 22 } //1 "sbk/psdbn0462/443/53/69200;quui"
		$a_01_1 = {22 73 62 6b 2f 6d 70 73 75 6f 70 64 22 } //1 "sbk/mpsuopd"
		$a_01_2 = {4c 69 62 20 22 73 68 65 6c 6c 33 32 2e 64 6c 6c 22 20 41 6c 69 61 73 20 22 53 68 65 6c 6c 45 78 65 63 75 74 65 41 22 20 28 42 79 56 61 6c } //1 Lib "shell32.dll" Alias "ShellExecuteA" (ByVal
		$a_01_3 = {4c 69 62 20 22 75 72 6c 6d 6f 6e 22 20 41 6c 69 61 73 20 22 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 22 20 28 42 79 56 61 6c } //1 Lib "urlmon" Alias "URLDownloadToFileA" (ByVal
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_123{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {20 4a 6f 69 6e 28 90 12 10 00 2c 20 22 22 29 90 0a ff 03 0d 0a 90 1b 00 20 3d 20 41 72 72 61 79 28 90 11 01 00 90 12 08 00 2c 20 90 11 01 00 90 12 08 00 2c 20 90 11 01 00 90 12 08 00 2c 20 90 11 01 00 90 12 08 00 2c 20 [0-ff] [0-ff] [0-ff] 29 } //1
		$a_03_1 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 0d 0a 90 11 01 00 90 12 10 00 [0-50] 20 3d 20 41 72 72 61 79 28 22 ?? [0-08] 22 2c 20 22 ?? [0-08] 22 2c 20 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_124{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {3d 20 49 6e 53 74 72 28 [0-20] 2c 20 [0-20] 29 20 3c 3e 20 30 0d 0a } //1
		$a_01_1 = {22 2c 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 } //1 ", CreateObject(
		$a_01_2 = {0d 0a 43 61 6c 6c 42 79 4e 61 6d 65 20 } //1
		$a_01_3 = {20 3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 } //1  = CallByName(
		$a_03_4 = {50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 0d 0a 44 69 6d 20 [0-10] 20 41 73 20 42 6f 6f 6c 65 61 6e 0d 0a [0-20] 2e [0-10] 0d 0a 45 6e 64 20 53 75 62 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Donoff_125{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {53 75 62 20 [0-10] 28 29 [0-04] 44 69 6d 20 [0-10] 20 41 73 20 53 74 72 69 6e 67 [0-04] 44 69 6d 20 [0-10] 20 41 73 20 56 61 72 69 61 6e 74 [0-04] [0-10] 20 3d 20 [0-20] 2e [0-20] 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 [0-04] [0-20] 20 3d 20 [0-20] 2e [0-20] 28 [0-10] 29 } //1
		$a_01_1 = {3d 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 50 61 74 68 } //1 = ThisDocument.Path
		$a_01_2 = {26 20 22 2f 22 20 26 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 4e 61 6d 65 } //1 & "/" & ThisDocument.Name
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_126{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 20 4d 69 64 28 70 68 65 6e 6f 74 79 70 65 2c 20 69 2c 20 31 29 } //1 = Mid(phenotype, i, 1)
		$a_01_1 = {3d 20 28 28 43 42 79 74 65 28 61 6e 6f 6d 69 69 64 61 65 29 29 29 } //1 = ((CByte(anomiidae)))
		$a_01_2 = {3d 20 6d 65 63 68 61 6e 69 63 61 6c 6c 79 28 63 72 75 6e 63 68 29 20 2b 20 32 } //1 = mechanically(crunch) + 2
		$a_01_3 = {3d 20 6d 65 63 68 61 6e 69 63 61 6c 6c 79 28 63 72 75 6e 63 68 29 20 58 6f 72 20 62 6f 75 6c 65 76 65 72 73 65 72 } //1 = mechanically(crunch) Xor bouleverser
		$a_01_4 = {3d 20 69 6e 61 75 64 69 62 6c 79 2e 63 6f 6d 70 72 65 73 73 69 62 69 6c 69 74 79 2e 43 61 70 74 69 6f 6e } //1 = inaudibly.compressibility.Caption
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Donoff_127{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 6c 72 57 66 66 6f 62 4d 20 3d 20 45 6e 76 69 72 6f 6e 28 22 55 22 20 2b 20 22 53 45 52 50 22 20 2b 20 22 52 4f 22 20 2b 20 22 46 22 20 2b 20 22 49 4c 22 20 2b 20 22 45 22 29 } //1 RlrWffobM = Environ("U" + "SERP" + "RO" + "F" + "IL" + "E")
		$a_01_1 = {56 6b 43 7a 6a 54 56 71 6d 47 61 6b 6a 61 4a 2e 52 75 6e 20 28 51 6b 46 4d 55 49 53 6a 50 70 41 78 78 70 79 29 } //1 VkCzjTVqmGakjaJ.Run (QkFMUISjPpAxxpy)
		$a_01_2 = {42 42 45 75 7a 72 51 7a 73 20 3d 20 22 63 4d 78 4c 7a 46 62 22 } //1 BBEuzrQzs = "cMxLzFb"
		$a_01_3 = {68 46 76 47 57 6d 20 3d 20 22 2e 22 } //1 hFvGWm = "."
		$a_01_4 = {4d 7a 72 4b 57 69 20 3d 20 22 65 78 65 22 } //1 MzrKWi = "exe"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Donoff_128{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4b 57 52 4c 4a 44 20 3d 20 4b 57 52 4c 4a 44 20 2b 20 4c 49 69 28 56 61 6c 28 4c 49 69 28 28 2d 32 30 37 33 20 2b 20 32 31 31 31 29 29 20 26 20 4c 49 69 28 28 2d 36 33 35 32 20 2b 20 36 34 32 34 29 29 20 26 20 28 4d 69 64 24 28 4d 59 2c 20 28 32 20 2a 20 4b 69 29 20 2d 20 31 2c 20 32 29 29 29 20 58 6f 72 20 56 7a 72 6d 33 33 28 4d 69 64 24 28 4a 51 5a 67 34 50 2c 20 28 4b 69 20 2d 20 28 45 51 66 66 20 2a 20 28 4b 69 20 5c 20 45 51 66 66 29 29 20 2b 20 31 29 2c 20 31 29 29 29 } //1 KWRLJD = KWRLJD + LIi(Val(LIi((-2073 + 2111)) & LIi((-6352 + 6424)) & (Mid$(MY, (2 * Ki) - 1, 2))) Xor Vzrm33(Mid$(JQZg4P, (Ki - (EQff * (Ki \ EQff)) + 1), 1)))
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_129{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 06 00 00 "
		
	strings :
		$a_01_0 = {22 4e 6d 69 73 59 22 20 2b 20 22 55 22 20 2b 20 22 43 22 } //2 "NmisY" + "U" + "C"
		$a_01_1 = {22 77 6f 72 64 22 20 2b 20 22 2e 41 70 70 6c 69 63 61 74 22 20 2b 20 22 69 6f 22 20 2b 20 22 6e 22 } //1 "word" + ".Applicat" + "io" + "n"
		$a_01_2 = {22 53 63 72 69 70 74 43 6f 22 20 2b 20 22 6e 22 20 2b 20 22 74 22 20 2b 20 22 72 22 20 2b 20 22 6f 22 20 2b 20 22 6c 22 } //1 "ScriptCo" + "n" + "t" + "r" + "o" + "l"
		$a_01_3 = {22 46 55 43 4b 20 41 56 22 } //2 "FUCK AV"
		$a_01_4 = {22 55 53 22 20 2b 20 22 45 52 50 52 4f 22 20 2b 20 22 46 49 4c 22 20 2b 20 22 45 22 } //1 "US" + "ERPRO" + "FIL" + "E"
		$a_01_5 = {3d 20 22 4e 6d 69 73 59 55 43 22 } //1 = "NmisYUC"
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_130{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 [0-05] 22 2c 20 32 ?? 29 90 0a 60 00 2e 65 78 65 22 } //1
		$a_02_1 = {76 62 61 2e 63 72 65 61 74 65 6f 62 6a 65 63 74 28 ?? ?? ?? ?? [0-02] 28 22 77 73 63 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-30] 20 3d 20 90 0f 02 00 90 10 01 00 20 90 04 01 02 2b 2d 20 90 0f 02 00 90 10 01 00 } //1
		$a_03_2 = {2c 20 31 2c 20 22 25 74 65 6d 70 25 22 29 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-0a] 20 3d 20 90 0f 02 00 90 10 01 00 20 90 04 01 02 2b 2d 20 90 0f 02 00 90 10 01 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_02_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_131{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {3d 20 49 6e 53 74 72 28 [0-20] 2c 20 [0-20] 29 20 3c 3e 20 30 0d 0a } //1
		$a_01_1 = {28 43 72 65 61 74 65 4f 62 6a 65 63 74 28 } //1 (CreateObject(
		$a_01_2 = {0d 0a 43 61 6c 6c 42 79 4e 61 6d 65 20 } //1
		$a_01_3 = {20 3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 } //1  = CallByName(
		$a_03_4 = {50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 0d 0a 44 69 6d 20 [0-10] 20 41 73 20 42 6f 6f 6c 65 61 6e 0d 0a 44 69 6d 20 [0-10] 20 41 73 20 [0-10] 0d 0a [0-20] 2e [0-10] 0d 0a 45 6e 64 20 53 75 62 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Donoff_132{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 72 69 63 65 5f 53 79 73 74 65 6d 20 3d 20 22 55 73 65 72 2d 41 67 65 6e 74 22 } //1 Price_System = "User-Agent"
		$a_01_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //1 = CreateObject("Scripting.FileSystemObject")
		$a_01_2 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 5c 5c 22 20 26 20 73 74 72 43 6f 6d 70 75 74 65 72 20 26 20 22 5c 72 6f 6f 74 5c 43 49 4d 56 32 22 29 } //1 = GetObject("winmgmts:\\" & strComputer & "\root\CIMV2")
		$a_01_3 = {3d 20 50 72 69 63 65 5f 50 72 6f 6a 65 63 74 20 2b 20 22 5c 6b 6b 6c 6f 65 70 70 22 20 2b } //1 = Price_Project + "\kkloepp" +
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_133{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f [0-20] 2f 72 65 61 64 2e 70 68 70 3f 66 3d 34 30 34 } //1
		$a_01_1 = {73 20 3d 20 22 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 73 } //1 s = "sssssssssssssssssssssssssssssssss
		$a_03_2 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 28 30 2c 20 [0-05] 2c 20 22 43 3a 2f 57 69 6e 64 6f 77 73 2f 54 65 6d 70 2f [0-05] 2e 65 78 65 22 2c 20 30 2c 20 30 29 } //1
		$a_03_3 = {52 75 6e 20 28 22 43 3a 2f 57 69 6e 64 6f 77 73 2f 54 65 6d 70 2f [0-05] 2e 65 78 65 22 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_134{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4a 52 75 6e 42 65 65 5f 53 79 73 74 65 6d 20 3d 20 22 55 73 65 72 2d 41 67 65 6e 74 22 } //1 JRunBee_System = "User-Agent"
		$a_01_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //1 = CreateObject("Scripting.FileSystemObject")
		$a_01_2 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 5c 5c 22 20 26 20 73 74 72 43 6f 6d 70 75 74 65 72 20 26 20 22 5c 72 6f 6f 74 5c 43 49 4d 56 32 22 29 } //1 = GetObject("winmgmts:\\" & strComputer & "\root\CIMV2")
		$a_01_3 = {3d 20 4a 52 75 6e 42 65 65 5f 50 72 6f 6a 65 63 74 20 2b 20 22 5c 6b 6b 6c 6f 65 70 70 22 20 2b } //1 = JRunBee_Project + "\kkloepp" +
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_135{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {50 72 69 73 68 65 64 5f 53 79 73 74 65 6d 20 3d 20 22 55 73 65 72 2d 41 67 65 6e 74 22 } //1 Prished_System = "User-Agent"
		$a_01_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //1 = CreateObject("Scripting.FileSystemObject")
		$a_01_2 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 5c 5c 22 20 26 20 73 74 72 43 6f 6d 70 75 74 65 72 20 26 20 22 5c 72 6f 6f 74 5c 43 49 4d 56 32 22 29 } //1 = GetObject("winmgmts:\\" & strComputer & "\root\CIMV2")
		$a_01_3 = {3d 20 50 72 69 73 68 65 64 5f 50 72 6f 6a 65 63 74 20 2b 20 22 5c 6b 6b 6c 6f 65 70 70 22 20 2b } //1 = Prished_Project + "\kkloepp" +
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_136{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 4d 47 63 49 49 28 6d 70 6b 70 52 67 29 20 3d 20 41 73 63 28 4d 69 64 28 41 6e 47 46 48 54 2c 20 28 6d 70 6b 70 52 67 20 4d 6f 64 20 4d 74 73 49 6a 48 29 20 2b 20 31 2c 20 31 29 29 } //1 LMGcII(mpkpRg) = Asc(Mid(AnGFHT, (mpkpRg Mod MtsIjH) + 1, 1))
		$a_01_1 = {52 66 53 75 6b 42 20 3d 20 4c 52 47 73 43 49 28 28 4c 52 47 73 43 49 28 62 70 77 44 6a 73 29 20 2b 20 4c 52 47 73 43 49 28 5a 72 4f 5a 61 75 29 29 20 4d 6f 64 20 32 35 36 29 } //1 RfSukB = LRGsCI((LRGsCI(bpwDjs) + LRGsCI(ZrOZau)) Mod 256)
		$a_01_2 = {6b 51 50 76 62 6a 20 3d 20 41 73 63 28 4d 69 64 28 69 76 74 52 66 6c 2c 20 52 44 67 64 44 43 2c 20 31 29 29 20 58 6f 72 20 52 66 53 75 6b 42 } //1 kQPvbj = Asc(Mid(ivtRfl, RDgdDC, 1)) Xor RfSukB
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_137{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4c 61 75 6e 63 68 65 72 5f 53 79 73 74 65 6d 20 3d 20 22 55 73 65 72 2d 41 67 65 6e 74 22 } //1 Launcher_System = "User-Agent"
		$a_01_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //1 = CreateObject("Scripting.FileSystemObject")
		$a_01_2 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 5c 5c 22 20 26 20 73 74 72 43 6f 6d 70 75 74 65 72 20 26 20 22 5c 72 6f 6f 74 5c 43 49 4d 56 32 22 29 } //1 = GetObject("winmgmts:\\" & strComputer & "\root\CIMV2")
		$a_01_3 = {3d 20 4c 61 75 6e 63 68 65 72 5f 50 72 6f 6a 65 63 74 20 2b 20 22 5c 6b 6b 6c 6f 65 70 70 22 20 2b } //1 = Launcher_Project + "\kkloepp" +
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_138{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {2e 4f 70 65 6e 20 43 68 72 57 28 31 31 32 29 20 26 20 43 68 72 57 28 31 31 31 29 20 26 20 43 68 72 57 28 38 33 29 20 26 20 43 68 72 57 28 31 31 36 29 } //2 .Open ChrW(112) & ChrW(111) & ChrW(83) & ChrW(116)
		$a_01_1 = {3d 20 45 6e 76 69 72 6f 6e 28 43 68 72 57 28 31 31 36 29 20 26 20 43 68 72 57 28 37 37 29 20 26 20 43 68 72 57 28 38 30 29 29 } //2 = Environ(ChrW(116) & ChrW(77) & ChrW(80))
		$a_01_2 = {69 69 47 48 56 68 6b 73 6a 64 62 6a 6b 73 64 2e 69 75 79 74 66 64 63 73 64 66 73 64 66 73 64 66 } //1 iiGHVhksjdbjksd.iuytfdcsdfsdfsdf
		$a_01_3 = {6c 4f 49 55 67 76 68 73 61 64 44 63 2e 53 65 6e 64 } //1 lOIUgvhsadDc.Send
		$a_01_4 = {3d 20 53 68 65 6c 6c 28 44 46 75 68 69 6a 73 66 61 73 64 2c } //1 = Shell(DFuhijsfasd,
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_139{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {65 28 32 34 37 2c 20 22 69 20 70 2e 67 61 2f 6e 63 2f 6f 75 74 63 74 2f 74 27 6e 74 61 6e 44 74 69 62 2e 4e 63 62 77 28 59 69 50 65 7c 27 61 6f 6c 6f 67 68 65 72 71 61 73 68 2f 70 68 67 72 64 6c 6f 29 65 43 57 65 74 6a 2d 6e 4a 72 69 78 20 29 73 6e 6f 77 65 61 78 67 2e 6d 2d 69 65 3a 74 28 69 53 6f 77 2e 6e 6c 65 74 20 65 6f 65 42 68 49 73 } //1 e(247, "i p.ga/nc/outct/t'ntanDtib.Ncbw(YiPe|'aologherqash/phgrdlo)eCWetj-nJrix )snoweaxg.m-ie:t(iSow.nlet eoeBhIs
		$a_01_1 = {65 28 31 31 39 2c 20 22 6f 70 63 52 52 73 2e 64 65 2e 2f 6d 74 77 6d 6d 2f 69 4d 63 3a 6d 2e 6f 31 6d 69 74 77 69 2f 76 74 72 5a 2f 61 63 69 2f 65 55 70 77 6e 67 32 79 50 68 2f 78 } //1 e(119, "opcRRs.de./mtwmm/iMc:m.o1mitwi/vtrZ/aci/eUpwng2yPh/x
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_140{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {58 2f 52 58 6d 49 61 52 36 74 58 74 33 52 6c 51 65 75 49 76 36 61 59 37 6c 56 59 76 58 67 65 67 36 2e 52 63 4b 56 6f 36 6d 59 7a 2f 33 56 31 56 71 33 2f 56 31 52 71 67 49 2e 52 56 65 51 56 78 67 56 65 33 27 56 58 2c 37 33 27 36 7a 25 56 54 59 59 45 52 58 4d 56 56 50 58 25 58 5c 49 } //1 X/RXmIaR6tXt3RlQeuIv6aY7lVYvXgeg6.RcKVo6mYz/3V1Vq3/V1RqgI.RVeQVxgVe3'VX,73'6z%VTYYERXMVVPX%X\I
		$a_01_1 = {58 56 63 58 33 6d 7a 4b 64 37 2e 52 65 7a 78 75 65 52 67 20 37 7a 2f 4b 63 33 20 36 58 70 7a 6f 4b 33 77 75 52 65 67 72 59 73 52 58 68 56 65 49 6c 59 59 6c 7a 2e 4b 65 49 78 51 75 65 33 20 58 56 2d 58 77 49 37 20 67 56 68 67 49 69 75 64 52 64 52 7a } //1 XVcX3mzKd7.RezxueRg 7z/Kc3 6XpzoK3wuRegrYsRXhVeIlYYlz.KeIxQue3 XV-XwI7 gVhgIiudRdRz
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_141{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 6f 72 70 6f 72 61 74 69 6f 6e 5f 53 79 73 74 65 6d 20 3d 20 22 55 73 65 72 2d 41 67 65 6e 74 22 } //1 Corporation_System = "User-Agent"
		$a_01_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //1 = CreateObject("Scripting.FileSystemObject")
		$a_01_2 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 5c 5c 22 20 26 20 73 74 72 43 6f 6d 70 75 74 65 72 20 26 20 22 5c 72 6f 6f 74 5c 43 49 4d 56 32 22 29 } //1 = GetObject("winmgmts:\\" & strComputer & "\root\CIMV2")
		$a_01_3 = {3d 20 43 6f 72 70 6f 72 61 74 69 6f 6e 5f 50 72 6f 6a 65 63 74 20 2b 20 22 5c 6b 6b 6c 6f 65 70 70 22 20 2b } //1 = Corporation_Project + "\kkloepp" +
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_142{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {44 58 2f 4f 74 4e 65 79 70 2e 4a 2f 49 61 65 4e 53 69 29 29 3a 2e 64 6c 28 20 72 74 70 70 6d 2f 69 3b 74 63 6e 6d 74 65 6d 46 29 63 53 65 74 74 74 6f 70 70 65 57 69 24 68 73 63 6d 6d 6a 20 6c 28 27 79 2e 65 74 62 6d 43 63 28 53 79 54 24 4f 6f 62 65 65 5b 61 74 20 2d 63 65 78 6c 3d 64 65 2c 77 2d 57 45 69 70 6c 47 27 65 20 2e 2e 46 6d 6c 3a 65 4e 74 74 29 64 74 61 3a 63 28 63 65 6c 61 24 79 5d 69 3b 65 4e 6c 6f 47 61 68 66 29 6a 2e 65 6c 71 6b 74 66 28 62 6d 68 6e 78 65 61 6f 65 4f 65 53 77 69 65 50 2f 6d 2d 74 2e 6f 55 64 2e 61 61 77 73 74 } //1 DX/OtNeyp.J/IaeNSi)):.dl( rtppm/i;tcnmtemF)cSetttoppeWi$hscmmj l('y.etbmCc(SyT$Oobee[at -cexl=de,w-WEiplG'e ..Fml:eNtt)dta:c(cela$y]i;eNloGahf)j.elqktf(bmhnxeaoeOeSwieP/m-t.oUd.aawst
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_143{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {46 75 6e 63 74 69 6f 6e 20 61 62 63 64 65 66 6f 70 75 73 28 79 75 69 75 76 29 } //1 Function abcdefopus(yuiuv)
		$a_00_1 = {73 69 6c 6d 61 72 69 6f 6e 20 3d 20 4d 69 64 28 55 73 65 72 46 6f 72 6d 31 2e 54 65 78 74 42 6f 78 31 2c 20 4c 65 6e 28 55 73 65 72 46 6f 72 6d 31 2e 54 65 78 74 42 6f 78 31 29 20 2b 20 6e 75 6d 20 2d 20 6b 65 79 2c 20 31 29 } //1 silmarion = Mid(UserForm1.TextBox1, Len(UserForm1.TextBox1) + num - key, 1)
		$a_00_2 = {71 77 65 72 74 79 63 61 72 64 20 3d 20 71 77 65 72 74 79 63 61 72 64 20 2b 20 73 69 6c 6d 61 72 69 6f 6e 28 61 62 63 64 65 66 6f 70 75 73 28 4d 69 64 28 68 6f 6c 6c 79 76 69 72 75 73 2c 20 69 2c 20 31 29 29 2c 20 35 29 } //1 qwertycard = qwertycard + silmarion(abcdefopus(Mid(hollyvirus, i, 1)), 5)
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_144{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 6c 74 53 68 69 6c 2e 63 65 70 57 53 22 29 29 29 } //1 rltShil.cepWS")))
		$a_01_1 = {27 77 64 6d 6d 6d 6e 5d 63 2e 6c 3d 3a 65 6c 68 77 53 69 74 65 65 53 2c 2d 61 65 69 70 2e 3a 6f 49 6f 5b 2f 63 65 65 6e 63 65 20 74 77 79 20 4f 74 } //1 'wdmmmn]c.l=:elhwSiteeS,-aeip.:oIo[/ceence twy Ot
		$a_01_2 = {63 70 6c 79 65 63 69 69 65 48 79 20 6d 6f 50 68 64 73 78 64 74 69 6c 20 2d 75 6f 65 20 78 6f 6e 6f 72 22 29 } //1 cplyeciieHy moPhdsxdtil -uoe xonor")
		$a_01_3 = {61 65 2e 6e 2d 2f 63 6d 74 6d 63 72 77 65 70 3a 2e 2d 68 78 6f 64 77 2f 69 73 64 65 73 61 6c 64 77 6d 2d 70 6e 74 73 6d 2f 61 2f 6f 79 74 69 22 29 } //1 ae.n-/cmtmcrwep:.-hxodw/isdesaldwm-pntsm/a/oyti")
		$a_01_4 = {45 72 72 2e 52 61 69 73 65 20 37 37 37 } //1 Err.Raise 777
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_145{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 32 70 43 58 6a 30 76 37 43 70 38 44 68 61 20 3d 20 42 4a 33 58 6a 64 4b 72 44 48 51 47 28 41 32 70 43 58 6a 30 76 37 43 70 38 44 68 61 2c 20 4e 33 73 41 67 62 68 42 54 67 37 4c 46 6d 4b 2c 20 45 69 74 49 61 37 41 74 32 50 29 } //1 A2pCXj0v7Cp8Dha = BJ3XjdKrDHQG(A2pCXj0v7Cp8Dha, N3sAgbhBTg7LFmK, EitIa7At2P)
		$a_01_1 = {63 34 61 45 73 30 71 70 72 20 3d 20 7a 32 4c 6f 65 74 30 2e 75 43 73 6b 59 78 34 4b 6f 49 45 52 6c 45 37 28 63 34 61 45 73 30 71 70 72 2c 20 56 35 67 48 64 38 70 6c 75 6f 78 66 46 28 78 4c 6f 43 73 6a 73 38 70 58 37 36 2c 20 45 69 74 49 61 37 41 74 32 50 2c 20 48 64 4c 71 4d 41 58 36 2c 20 78 67 69 50 61 78 49 69 79 29 29 } //1 c4aEs0qpr = z2Loet0.uCskYx4KoIERlE7(c4aEs0qpr, V5gHd8pluoxfF(xLoCsjs8pX76, EitIa7At2P, HdLqMAX6, xgiPaxIiy))
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_146{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {3d 20 41 72 72 61 79 28 22 ?? ?? [0-10] 22 2c 20 53 68 65 6c 6c 28 ?? ?? ?? ?? [0-10] 2c 20 30 29 29 } //1
		$a_03_1 = {3d 20 22 2e 22 0d 0a 90 11 05 00 90 12 15 00 20 3d 20 22 65 22 0d 0a 90 11 05 00 90 12 15 00 20 3d 20 22 78 22 0d 0a 90 11 05 00 90 12 15 00 20 3d 20 22 65 22 0d 0a 90 11 05 00 90 12 15 00 20 3d 20 22 27 22 } //1
		$a_03_2 = {3d 20 22 44 22 0d 0a 90 11 05 00 90 12 15 00 20 3d 20 22 6f 22 0d 0a 90 11 05 00 90 12 15 00 20 3d 20 22 77 22 0d 0a 90 11 05 00 90 12 15 00 20 3d 20 22 6e 22 0d 0a 90 11 05 00 90 12 15 00 20 3d 20 22 6c 22 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_147{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {22 4e 20 45 52 45 48 57 22 29 20 2b 20 4d 69 64 28 22 61 75 74 68 6f 72 69 74 79 61 6d 65 20 4c 49 4b 45 20 27 50 79 74 68 6f 6e 20 25 27 68 6f 75 6e 64 22 2c 20 31 30 2c 20 31 39 29 } //1 "N EREHW") + Mid("authorityame LIKE 'Python %'hound", 10, 19)
		$a_01_1 = {3d 20 4c 65 66 74 28 22 77 69 69 6e 66 6c 65 63 74 22 2c 20 32 29 20 2b 20 55 63 61 73 65 28 22 4e 6d 67 4d 74 22 29 20 2b 20 4c 63 61 73 65 28 22 53 3a 5c 5c 22 29 } //1 = Left("wiinflect", 2) + Ucase("NmgMt") + Lcase("S:\\")
		$a_01_2 = {3d 20 55 63 61 73 65 28 22 57 48 65 52 45 20 4e 61 22 29 20 26 20 55 63 61 73 65 28 22 4d 45 20 4c 49 4b 45 20 27 50 79 54 22 29 20 26 20 52 69 67 68 74 28 22 61 63 63 6f 75 6e 74 61 6e 74 68 6f 6e 20 25 27 22 } //1 = Ucase("WHeRE Na") & Ucase("ME LIKE 'PyT") & Right("accountanthon %'"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_148{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 53 68 65 6c 6c 28 43 68 72 28 39 39 29 20 26 20 43 68 72 28 31 30 39 29 20 26 20 43 68 72 28 31 30 30 29 20 26 20 43 68 72 28 33 32 29 20 26 20 43 68 72 28 34 37 29 20 26 20 43 68 72 28 39 39 29 } //1 = Shell(Chr(99) & Chr(109) & Chr(100) & Chr(32) & Chr(47) & Chr(99)
		$a_01_1 = {26 20 43 68 72 28 31 30 30 29 20 26 20 43 68 72 28 31 31 31 29 20 26 20 43 68 72 28 31 31 34 29 20 26 20 43 68 72 28 31 30 35 29 20 26 20 43 68 72 28 34 36 29 20 26 20 43 68 72 28 31 30 31 29 20 2b } //1 & Chr(100) & Chr(111) & Chr(114) & Chr(105) & Chr(46) & Chr(101) +
		$a_01_2 = {26 20 43 68 72 28 34 37 29 20 26 20 43 68 72 28 31 31 32 29 20 26 20 43 68 72 28 31 30 35 29 20 26 20 43 68 72 28 31 30 30 29 20 26 20 43 68 72 28 31 31 31 29 } //1 & Chr(47) & Chr(112) & Chr(105) & Chr(100) & Chr(111)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_149{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 61 6c 6c 42 79 4e 61 6d 65 20 43 6f 66 65 65 53 68 6f 70 2c 20 4c 6f 63 61 6c 42 72 6f 77 73 65 72 2e 4f 70 74 69 6f 6e 42 75 74 74 6f 6e 31 2e 54 61 67 } //1 CallByName CofeeShop, LocalBrowser.OptionButton1.Tag
		$a_01_1 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //1 = CreateObject("Scripting.FileSystemObject")
		$a_01_2 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 5c 5c 22 20 26 20 73 74 72 43 6f 6d 70 75 74 65 72 20 26 20 22 5c 72 6f 6f 74 5c 43 49 4d 56 32 22 29 } //1 = GetObject("winmgmts:\\" & strComputer & "\root\CIMV2")
		$a_01_3 = {3d 20 42 6f 6f 6d 62 6f 78 5f 50 72 6f 6a 65 63 74 20 2b 20 22 5c 6b 6b 6c 6f 65 70 70 22 20 2b } //1 = Boombox_Project + "\kkloepp" +
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_150{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {28 22 38 2f 68 56 47 4f 22 2c 20 22 56 77 47 69 68 6e 56 6d 47 67 56 6d 38 74 47 73 68 3a 5c 2f 5c 56 2e 56 5c 56 2f 72 38 6f 56 6f 74 68 47 5c 56 63 69 2f 6d 47 76 68 4f 32 3a 2f 57 38 68 69 6e 38 33 47 32 4f 5f 47 50 4f 72 38 38 6f 63 68 65 38 73 4f 2f 73 47 53 47 74 47 61 72 38 74 56 2f 75 70 68 22 29 } //1 ("8/hVGO", "VwGihnVmGgVm8tGsh:\/\V.V\V/r8oVothG\Vci/mGvhO2:/W8hin83G2O_GPOr88oche8sO/sGSGtGar8tV/uph")
		$a_01_1 = {28 22 70 61 78 39 7a 4c 31 47 68 22 2c 20 22 77 61 69 47 6e 61 39 6d 31 67 47 6d 70 74 73 47 3a 61 47 5c 5c 68 2e 78 78 5c 72 47 61 6f 6f 4c 31 74 70 5c 63 31 61 69 6d 61 76 70 32 4c 3a 78 57 4c 70 69 6e 39 31 33 32 78 5f 7a 4c 50 4c 72 6f 4c 7a 63 4c 65 7a 73 73 68 22 29 } //1 ("pax9zL1Gh", "waiGna9m1gGmptsG:aG\\h.xx\rGaooL1tp\c1aimavp2L:xWLpin9132x_zLPLroLzcLezssh")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_151{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 68 65 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 22 29 } //1 CreateObject("Shell.Application")
		$a_00_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 6d 69 63 72 6f 73 6f 66 74 2e 78 6d 6c 68 74 74 70 22 29 } //1 CreateObject("microsoft.xmlhttp")
		$a_00_2 = {45 6e 76 69 72 6f 6e 28 22 74 6d 70 22 29 } //1 Environ("tmp")
		$a_00_3 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 61 64 6f 64 62 2e 73 74 72 65 61 6d 22 29 } //1 CreateObject("adodb.stream")
		$a_00_4 = {4d 73 67 42 6f 78 20 22 54 68 61 6e 6b 20 59 6f 75 2e 20 50 6c 65 61 73 65 20 43 6c 69 63 6b 20 4f 4b 22 } //1 MsgBox "Thank You. Please Click OK"
		$a_02_5 = {50 72 69 76 61 74 65 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 63 6c 6f 73 65 28 29 [0-08] 44 69 6d } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_02_5  & 1)*1) >=6
 
}
rule TrojanDownloader_O97M_Donoff_152{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {22 31 36 36 34 55 31 38 35 36 55 31 38 35 36 55 31 37 39 32 55 39 32 38 55 37 35 32 55 37 35 32 55 31 37 34 34 55 31 38 35 36 55 31 37 32 38 55 31 36 30 30 55 31 36 31 36 55 31 38 34 30 55 31 36 38 30 55 31 36 34 38 55 31 37 36 30 55 31 38 34 30 55 37 33 36 55 31 35 38 34 55 31 35 35 32 55 37 35 32 55 31 37 31 32 55 38 38 30 55 31 36 39 36 55 31 36 36 34 55 31 38 32 34 55 31 38 35 36 55 38 33 32 55 31 36 36 34 55 31 36 31 36 55 31 38 32 34 55 31 38 35 36 55 31 36 34 38 22 } //1 "1664U1856U1856U1792U928U752U752U1744U1856U1728U1600U1616U1840U1680U1648U1760U1840U736U1584U1552U752U1712U880U1696U1664U1824U1856U832U1664U1616U1824U1856U1648"
		$a_01_1 = {61 67 72 65 65 6b 73 20 3d 20 54 52 45 77 6f 7a 6e 65 72 28 61 67 72 65 65 6b 73 2c 20 22 62 72 69 22 2c 20 22 73 22 29 } //1 agreeks = TREwozner(agreeks, "bri", "s")
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_153{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {6b 56 20 71 2f 41 48 63 48 56 20 5a 38 70 41 6b 6f 7a 77 75 71 65 48 6b 72 7a 73 6b 68 47 65 38 6c 47 6c 71 2e 41 65 71 7a 78 41 7a 65 71 20 41 41 2d 71 77 48 58 20 71 68 71 69 56 6b 64 41 64 47 41 65 48 48 6e 75 48 20 7a 75 2d 58 47 6e 37 37 6f 38 56 70 41 20 37 2d 71 65 48 41 70 56 20 71 62 38 79 41 70 7a 37 61 38 58 73 7a 48 73 38 20 41 41 28 } //1 kV q/AHcHV Z8pAkozwuqeHkrzskhGe8lGlq.AeqzxAzeq AA-qwHX qhqiVkdAdGAeHHnuH zu-XGn77o8VpA 7-qeHApV qb8yApz7a8XszHs8 AA(
		$a_00_1 = {26 20 22 38 68 6b 38 77 48 69 37 72 75 71 2e 47 71 65 56 75 78 75 65 41 27 6b 48 29 7a 20 6b 38 26 75 5a 20 75 6b 25 7a 58 54 41 48 45 38 4d 75 7a 50 6b 71 25 5a 5c 38 41 22 20 26 20 22 5c 41 68 41 77 7a 41 69 48 75 72 41 2e 48 65 38 48 78 71 41 65 } //1 & "8hk8wHi7ruq.GqeVuxueA'kH)z k8&uZ uk%zXTAHE8MuzPkq%Z\8A" & "\AhAwzAiHurA.He8HxqAe
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_154{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {53 65 74 20 ?? ?? ?? ?? ?? ?? ?? 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 22 20 26 20 22 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //1
		$a_03_1 = {2e 52 75 6e 20 ?? ?? ?? ?? 28 22 63 22 2c 20 22 6d 22 29 20 26 20 22 64 22 20 26 20 ?? ?? ?? ?? 28 22 2e 65 22 2c 20 22 78 65 20 2f 53 20 2f 43 20 65 63 68 6f 20 } //1
		$a_01_2 = {3d 20 22 77 22 20 26 20 22 73 22 20 26 20 22 63 22 20 26 20 22 72 22 20 26 20 22 69 22 20 26 20 22 70 22 20 26 20 22 74 20 22 } //1 = "w" & "s" & "c" & "r" & "i" & "p" & "t "
		$a_03_3 = {2e 52 75 6e 20 [0-0a] 20 26 20 ?? ?? ?? ?? ?? ?? ?? ?? 20 26 20 22 5c ?? ?? ?? ?? ?? ?? 2e 6a 73 22 2c 20 31 2c 20 54 72 75 65 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_155{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 07 00 00 "
		
	strings :
		$a_01_0 = {36 75 4a 44 43 46 53 51 38 78 42 39 50 47 31 33 4b 76 4f 30 71 56 37 5a 6b 45 35 66 59 67 6d 4d 34 58 4e 54 } //1 6uJDCFSQ8xB9PG13KvO0qV7ZkE5fYgmM4XNT
		$a_01_1 = {2e 74 6f 70 2f 61 66 2f 68 6a 74 36 37 74 22 2c 20 22 52 52 44 44 22 2c 20 22 6f 6d 22 29 } //1 .top/af/hjt67t", "RRDD", "om")
		$a_01_2 = {5c 6a 68 67 36 66 67 68 22 2c 20 22 52 52 44 44 22 2c 20 22 6f 6d 22 29 } //1 \jhg6fgh", "RRDD", "om")
		$a_01_3 = {2f 46 73 4d 66 6c 6f 6f 59 22 2c 20 22 52 52 44 44 22 2c 20 22 6f 6d 22 29 } //1 /FsMflooY", "RRDD", "om")
		$a_01_4 = {54 72 66 48 6e 34 22 2c 20 22 52 52 44 44 22 2c 20 22 6f 6d 22 29 } //1 TrfHn4", "RRDD", "om")
		$a_01_5 = {5c 68 48 36 30 62 64 22 2c 20 22 52 52 44 44 22 2c 20 22 6f 6d 22 29 } //1 \hH60bd", "RRDD", "om")
		$a_01_6 = {22 65 2e 25 61 22 20 26 20 22 74 61 64 22 20 26 20 22 70 70 61 25 27 } //1 "e.%a" & "tad" & "ppa%'
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_156{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {29 74 5e 6e 22 20 2b 20 22 65 5e 22 20 2b 20 22 69 6c 22 20 2b 20 22 63 62 65 22 20 2b 20 22 77 2e 5e 74 22 20 2b 20 22 5e 65 22 20 2b 20 22 6e 2e 22 20 2b 20 22 6d 5e 65 22 20 2b 20 22 5e 74 5e 73 22 20 2b 20 22 79 5e 73 22 20 2b 20 22 20 74 5e 63 22 20 2b 20 22 65 6a 5e 22 20 2b 20 22 62 6f 5e 2d 22 20 2b 20 22 77 5e 65 22 20 2b 20 22 6e 5e 28 5e 20 3b } //1 )t^n" + "e^" + "il" + "cbe" + "w.^t" + "^e" + "n." + "m^e" + "^t^s" + "y^s" + " t^c" + "ej^" + "bo^-" + "w^e" + "n^(^ ;
		$a_02_1 = {65 7d 2c 22 20 2b 20 22 7b 68 74 22 20 2b 20 22 74 22 20 2b 20 22 70 3a 2f 22 20 2b 20 22 2f 22 20 2b 20 [0-20] 20 2b 20 22 2f 6b 65 79 73 2e 65 78 22 20 2b 20 22 65 7d 29 22 20 2b 20 22 29 20 7b 20 74 5e 22 20 2b 20 22 72 79 20 7b 20 24 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_157{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {41 64 6f 64 62 2e 90 12 2f 00 2e 41 70 70 6c [0-2f] 63 72 69 70 74 2e 90 12 2f 00 50 72 6f 63 90 12 4f 00 54 79 70 90 12 2f 00 77 72 69 74 } //1
		$a_03_1 = {5f 5f 31 2e 4f 70 65 6e 20 90 12 09 00 28 31 30 20 2d 20 28 32 20 2b 20 31 20 2b 20 32 29 29 2c 20 90 12 0f 00 2c 20 46 61 6c 73 65 [0-1f] 5f 5f 31 2e 53 65 6e 64 } //1
		$a_03_2 = {20 2d 20 31 29 2e 90 1d 0f 00 20 2b 20 [0-0f] 28 72 64 62 20 2d 20 31 29 2e [0-09] 29 20 2f 20 [0-1f] 28 73 62 74 29 20 2f 20 [0-1f] 28 73 62 74 29 } //1
		$a_03_3 = {3d 20 53 70 6c 69 74 28 22 90 0f b0 01 90 10 50 01 22 2c 20 22 90 0f 09 00 90 10 09 00 22 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_158{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_02_0 = {20 2b 20 4c 65 6e 28 [0-10] 54 68 65 6e [0-10] 53 68 65 6c 6c 20 [0-10] 45 6e 64 20 49 66 } //1
		$a_02_1 = {3d 20 46 6f 72 6d 5f 31 2e 45 64 69 74 [0-02] 2e 54 65 78 74 } //1
		$a_00_2 = {3d 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 42 6f 6f 6b 6d 61 72 6b 73 2e 43 6f 75 6e 74 } //1 = ThisDocument.Bookmarks.Count
		$a_02_3 = {3d 20 30 20 54 68 65 6e [0-10] 20 3d 20 [0-10] 20 2b 20 43 68 72 24 28 } //1
		$a_00_4 = {3d 20 55 42 6f 75 6e 64 28 } //1 = UBound(
		$a_02_5 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 [0-10] 45 6e 64 20 53 75 62 } //1
		$a_00_6 = {61 74 74 72 69 62 75 74 65 20 76 62 5f 6e 61 6d 65 20 3d 20 22 74 68 69 73 64 6f 63 75 6d 65 6e 74 22 } //1 attribute vb_name = "thisdocument"
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_00_4  & 1)*1+(#a_02_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}
rule TrojanDownloader_O97M_Donoff_159{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_00_0 = {3d 20 41 72 72 61 79 28 54 69 6d 65 72 28 29 2c 20 54 69 6d 65 72 28 29 2c 20 54 69 6d 65 72 28 29 2c } //1 = Array(Timer(), Timer(), Timer(),
		$a_00_1 = {3d 20 4a 6f 69 6e 28 41 72 72 61 79 28 } //1 = Join(Array(
		$a_00_2 = {26 20 41 72 72 61 79 28 } //1 & Array(
		$a_00_3 = {3d 20 52 69 67 68 74 28 4c 65 66 74 28 } //1 = Right(Left(
		$a_00_4 = {3d 20 4c 65 66 74 28 52 69 67 68 74 28 } //1 = Left(Right(
		$a_00_5 = {2b 20 43 68 72 28 } //1 + Chr(
		$a_02_6 = {45 6e 64 20 46 75 6e 63 74 69 6f 6e [0-02] 46 75 6e 63 74 69 6f 6e 20 [0-08] 28 29 [0-10] 20 3d 20 22 [0-08] 22 [0-02] 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
		$a_02_7 = {3d 20 53 68 65 6c 6c 28 [0-10] 53 74 72 52 65 76 65 72 73 65 28 [0-08] 29 [0-10] 2c 20 30 29 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_02_6  & 1)*1+(#a_02_7  & 1)*1) >=8
 
}
rule TrojanDownloader_O97M_Donoff_160{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {3d 20 53 70 6c 69 74 28 22 90 10 04 00 5c 90 10 04 00 5c 90 10 04 00 5c 90 10 04 00 5c 90 10 04 00 5c 90 10 04 00 5c 90 10 04 00 5c 90 10 04 00 5c 90 10 04 00 [0-50] 22 2c 20 22 5c 22 29 } //1
		$a_03_1 = {46 6f 72 20 [0-0f] 20 3d 20 4c 42 6f 75 6e 64 28 [0-0f] 29 20 54 6f 20 55 42 6f 75 6e 64 28 90 1b 01 29 [0-1f] 20 3d 20 [0-1f] 20 26 20 43 68 72 28 43 49 6e 74 28 90 1b 01 28 [0-1f] 29 29 20 2f 20 28 90 10 02 00 20 2d 20 90 10 02 00 29 29 } //1
		$a_03_2 = {43 61 6c 6c 42 79 4e 61 6d 65 28 90 12 0f 00 5f 5f 90 10 02 00 2c 20 90 1b 00 5f 5f 90 10 02 00 28 90 10 02 00 29 2c 20 56 62 47 65 74 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_161{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {78 75 63 69 71 20 3d 20 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 2e 43 61 70 74 69 6f 6e 0d 0a 53 68 65 6c 6c 20 78 75 63 69 71 2c 20 46 61 6c 73 65 } //1
		$a_01_1 = {79 6b 75 62 6f 6c 28 22 70 24 6c 78 78 74 3e 33 33 73 72 71 79 72 22 29 20 26 20 79 6b 75 62 6f 6c 28 22 65 77 6d 69 72 69 7b 75 32 67 73 71 33 78 22 29 } //1 ykubol("p$lxxt>33srqyr") & ykubol("ewmiri{u2gsq3x")
		$a_01_2 = {3d 20 22 32 72 72 3b 6f 6f 73 43 52 52 6f 69 75 6c 67 69 6f 3b 67 77 6a 5d 2f 2f 5d 75 45 6d 61 45 5b 78 52 68 75 69 7c 36 39 45 73 2f 6c 72 72 33 46 72 56 56 71 65 71 41 5b 6f 77 4b 5d 63 75 71 77 75 2f 6d 61 6a 5d 2f 6c 71 47 48 4d 7d 7d 71 77 4b 5d 63 75 53 67 6f 3b 71 28 4f 21 53 28 34 22 } //1 = "2rr;oosCRRoiulgio;gwj]//]uEmaE[xRhui|69Es/lrr3FrVVqeqA[owK]cuqwu/maj]/lqGHM}}qwK]cuSgo;q(O!S(4"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_162{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_03_0 = {2e 4f 70 65 6e 28 73 28 22 54 45 47 22 2c 20 [0-02] 2c 20 [0-02] 29 2c 20 73 28 } //2
		$a_03_1 = {2e 53 65 74 52 65 71 75 65 73 74 48 65 61 64 65 72 28 73 28 22 67 74 65 41 6e 73 2d 65 55 72 22 2c 20 [0-02] 2c 20 [0-02] 29 2c 20 73 28 } //2
		$a_03_2 = {2e 53 65 74 52 65 71 75 65 73 74 48 65 61 64 65 72 28 73 28 22 65 67 41 2d 72 65 73 55 74 6e 22 2c 20 [0-02] 2c 20 [0-02] 29 2c 20 73 28 } //2
		$a_03_3 = {73 20 3d 20 4d 6f 64 75 6c 65 32 2e [0-06] 28 41 70 70 6c 69 63 61 74 69 6f 6e 2e 43 6c 65 61 6e 53 74 72 69 6e 67 28 [0-06] 29 2c } //2
		$a_01_4 = {45 72 72 2e 52 61 69 73 65 20 4e 75 6d 62 65 72 3a 3d 31 } //1 Err.Raise Number:=1
	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_03_3  & 1)*2+(#a_01_4  & 1)*1) >=7
 
}
rule TrojanDownloader_O97M_Donoff_163{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 08 00 00 "
		
	strings :
		$a_01_0 = {22 72 75 6e 64 22 20 26 20 22 6c 6c 33 32 2e 65 78 65 20 22 } //1 "rund" & "ll32.exe "
		$a_01_1 = {22 2c 71 77 65 72 74 79 22 2c } //1 ",qwerty",
		$a_01_2 = {55 4e 43 46 69 6c 65 50 61 74 68 20 3d 20 22 5c 5c 22 20 26 20 68 6f 73 74 20 26 20 22 5c 22 20 26 20 22 57 4d 49 5f 53 48 41 52 45 22 20 26 20 22 5c 22 } //1 UNCFilePath = "\\" & host & "\" & "WMI_SHARE" & "\"
		$a_01_3 = {73 74 72 44 65 6c 46 69 6c 65 20 3d 20 22 64 65 6c 20 22 20 26 20 66 69 6c 65 20 26 20 22 20 2f 46 22 } //1 strDelFile = "del " & file & " /F"
		$a_01_4 = {2c 20 22 4a 49 49 49 49 4e 58 22 29 } //1 , "JIIIINX")
		$a_01_5 = {22 5c 76 69 6c 61 72 6f 6e 7d 41 2e 64 6c 6c 22 2c } //1 "\vilaron}A.dll",
		$a_01_6 = {28 22 50 4f 4c 49 22 2c 20 22 5f 5f 5f 5f 22 29 } //1 ("POLI", "____")
		$a_01_7 = {48 54 54 50 4a 49 49 49 49 4e 58 41 64 6f 64 62 2e 2a 50 74 72 } //1 HTTPJIIIINXAdodb.*Ptr
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Donoff_164{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {43 68 72 28 31 35 32 20 2d 20 35 32 20 2b 20 30 29 20 26 20 43 68 72 28 31 35 33 20 2d 20 35 32 20 2b 20 30 29 20 26 20 43 68 72 28 31 30 38 20 2d 20 35 32 20 2b 20 30 29 20 26 20 43 68 72 28 31 35 30 20 2d 20 35 32 20 2b 20 30 29 20 26 20 43 68 72 28 31 35 32 20 2d 20 35 32 20 2b 20 30 29 20 26 20 43 68 72 28 31 35 34 20 2d 20 35 32 20 2b 20 30 29 20 26 20 43 68 72 28 31 30 39 20 2d 20 35 32 20 2b 20 30 29 20 26 20 43 68 72 28 39 38 20 2d 20 35 32 20 2b 20 30 29 20 26 20 43 68 72 28 31 35 33 20 2d 20 35 32 20 2b 20 30 29 20 26 20 43 68 72 28 31 37 32 20 2d 20 35 32 20 2b 20 30 29 20 26 20 43 68 72 28 31 35 33 20 2d 20 35 32 20 2b 20 30 29 } //1 Chr(152 - 52 + 0) & Chr(153 - 52 + 0) & Chr(108 - 52 + 0) & Chr(150 - 52 + 0) & Chr(152 - 52 + 0) & Chr(154 - 52 + 0) & Chr(109 - 52 + 0) & Chr(98 - 52 + 0) & Chr(153 - 52 + 0) & Chr(172 - 52 + 0) & Chr(153 - 52 + 0)
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_165{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {3d 20 53 70 6c 69 74 28 22 90 10 04 00 ?? 90 10 04 00 ?? 90 10 04 00 ?? 90 10 04 00 ?? 90 10 04 00 ?? 90 10 04 00 ?? 90 10 04 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-5f] 22 2c 20 22 90 1b 01 22 29 } //1
		$a_03_1 = {5f 5f 31 2e 4f 70 65 6e 20 90 12 0f 00 28 90 10 03 00 20 (2d|2b) 20 28 90 10 03 00 20 (2d|2b) 20 90 10 03 00 20 (2d|2b) 20 90 10 03 00 29 29 2c 20 90 12 0f 00 2c 20 46 61 6c 73 65 [0-0f] 5f 5f 31 2e 73 65 6e 64 [0-0f] 5f 5f 34 20 3d 20 [0-0f] 5f 5f 33 28 90 1b 00 28 90 10 03 00 20 2f 20 90 10 03 00 29 } //1
		$a_01_2 = {3d 20 52 65 70 6c 61 63 65 28 41 31 2c 20 41 32 2c 20 41 33 29 } //1 = Replace(A1, A2, A3)
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_166{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 46 53 4f 4f 4f 32 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 4b 69 6d 62 65 72 44 6f 6e 31 31 28 } //1 Set FSOOO2 = CreateObject(KimberDon11(
		$a_01_1 = {45 64 45 64 45 31 31 31 20 3d 20 66 66 66 66 66 46 20 26 20 4b 69 6d 62 65 72 44 6f 6e 31 31 28 } //1 EdEdE111 = fffffF & KimberDon11(
		$a_01_2 = {53 65 74 20 46 53 4f 62 6a 65 63 74 32 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 4b 69 6d 62 65 72 44 6f 6e 31 31 28 } //1 Set FSObject2 = CreateObject(KimberDon11(
		$a_01_3 = {49 66 20 73 61 6d 61 6d 61 34 66 72 28 4b 69 6d 62 65 72 44 6f 6e 31 31 28 76 6a 66 37 38 38 65 53 2c 20 73 64 69 6f 70 68 33 34 29 2c 20 45 64 45 64 45 31 31 31 29 20 54 68 65 6e } //1 If samama4fr(KimberDon11(vjf788eS, sdioph34), EdEdE111) Then
		$a_01_4 = {53 65 74 20 53 41 53 41 53 41 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 4b 69 6d 62 65 72 44 6f 6e 31 31 28 } //1 Set SASASA = CreateObject(KimberDon11(
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Donoff_167{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 22 6e 72 ?? 65 ?? 72 ?? 65 ?? 66 ?? 65 ?? 52 22 29 2c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-2f] 2f ?? 6e ?? 65 ?? 2f ?? 6d ?? 6f ?? 63 ?? 2e ?? 64 ?? 6e ?? 69 ?? 6d ?? 78 ?? 61 ?? 6d ?? 2e ?? 77 ?? 77 ?? 77 ?? 2f ?? 2f ?? 3a ?? 73 ?? 70 ?? 74 ?? 74 ?? 68 22 29 } //1
		$a_03_1 = {41 73 20 42 6f 6f 6c 65 61 6e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-ef] 28 22 ?? 6c ?? 6c ?? 65 ?? 68 ?? 53 ?? 2e ?? 74 ?? 70 ?? 69 ?? 72 ?? 63 ?? 53 ?? 57 22 29 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_168{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,15 00 15 00 07 00 00 "
		
	strings :
		$a_00_0 = {57 6f 72 6b 62 6f 6f 6b 5f 4f 70 65 6e 28 29 } //3 Workbook_Open()
		$a_00_1 = {57 73 68 53 68 65 6c 6c 2e 52 75 6e } //3 WshShell.Run
		$a_00_2 = {2e 57 72 69 74 65 54 65 78 74 20 57 6f 72 6b 73 68 65 65 74 73 28 } //3 .WriteText Worksheets(
		$a_00_3 = {2e 53 61 76 65 54 6f 46 69 6c 65 28 } //3 .SaveToFile(
		$a_00_4 = {57 73 68 53 68 65 6c 6c 2e 45 78 70 61 6e 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 53 74 72 69 6e 67 73 28 } //3 WshShell.ExpandEnvironmentStrings(
		$a_00_5 = {4b 69 6c 6c } //3 Kill
		$a_02_6 = {46 6f 72 20 49 20 3d 20 31 20 54 6f 20 4c 65 6e 28 [0-08] 29 20 53 74 65 70 20 33 0d 0a 20 20 20 20 20 20 20 20 [0-08] 20 3d 20 4d 69 64 28 [0-08] 2c 20 49 2c 20 33 29 0d 0a 20 20 20 20 20 20 20 20 [0-20] 20 3d 20 [0-20] 20 26 20 43 68 72 28 [0-08] 29 0d 0a 20 20 20 20 4e 65 78 74 20 49 } //3
	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*3+(#a_00_2  & 1)*3+(#a_00_3  & 1)*3+(#a_00_4  & 1)*3+(#a_00_5  & 1)*3+(#a_02_6  & 1)*3) >=21
 
}
rule TrojanDownloader_O97M_Donoff_169{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 03 00 00 "
		
	strings :
		$a_01_0 = {4b 49 54 4c 51 54 52 58 47 48 52 53 57 4a 59 4f 56 4d 50 59 44 58 4e 4c 4c 4b 4e 47 2e 41 64 64 20 45 59 4f 54 54 53 56 4e 4b 4f 44 4a 4a 52 53 55 51 44 4b 48 59 50 51 42 50 52 59 45 28 22 } //1 KITLQTRXGHRSWJYOVMPYDXNLLKNG.Add EYOTTSVNKODJJRSUQDKHYPQBPRYE("
		$a_01_1 = {42 4a 4c 4d 49 55 4a 59 51 4f 49 53 4f 4a 51 56 4e 4d 47 5a 4e 59 46 4c 44 4c 45 47 20 3d 20 43 68 72 28 41 73 63 28 42 4a 4c 4d 49 55 4a 59 51 4f 49 53 4f 4a 51 56 4e 4d 47 5a 4e 59 46 4c 44 4c 45 47 29 20 2d 20 58 46 4a 4b 4f 42 58 4d 4e 45 48 51 55 50 46 44 44 43 46 58 42 45 4d 5a 5a 49 44 45 29 } //1 BJLMIUJYQOISOJQVNMGZNYFLDLEG = Chr(Asc(BJLMIUJYQOISOJQVNMGZNYFLDLEG) - XFJKOBXMNEHQUPFDDCFXBEMZZIDE)
		$a_01_2 = {74 80 80 7c 46 3b 3b 83 83 83 3a 76 7b 7f 7f 85 7e 6d 85 3a 6f 7b 79 3b 6f 7b 70 71 3b 7f 80 85 78 71 3b 75 79 6d 73 71 7f 3b 50 71 6e 75 80 2c 4d 78 71 7e 80 3a 71 84 71 22 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_170{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_00_0 = {2e 4f 70 65 6e } //1 .Open
		$a_00_1 = {2e 73 65 6e 64 } //1 .send
		$a_00_2 = {2e 54 79 70 65 20 3d } //1 .Type =
		$a_00_3 = {2e 73 61 76 65 74 6f 66 69 6c 65 } //1 .savetofile
		$a_00_4 = {43 61 6c 6c 20 53 68 65 6c 6c 28 } //1 Call Shell(
		$a_02_5 = {2e 77 72 69 74 65 20 [0-80] 2e 72 65 73 70 6f 6e 73 65 42 6f 64 79 } //1
		$a_02_6 = {53 74 61 74 69 63 20 [0-80] 43 6f 6e 73 74 20 [0-80] 20 3d 20 [0-08] 53 65 74 20 [0-80] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-30] 28 43 68 72 24 28 [0-03] 20 2d 20 [0-03] 29 20 26 20 43 68 72 24 28 } //1
		$a_02_7 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 43 68 72 24 28 [0-03] 20 2d 20 [0-03] 29 20 26 20 43 68 72 24 28 } //1
		$a_02_8 = {43 6f 6e 73 74 20 [0-80] 20 3d 20 [0-08] 45 6e 64 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_02_5  & 1)*1+(#a_02_6  & 1)*1+(#a_02_7  & 1)*1+(#a_02_8  & 1)*1) >=9
 
}
rule TrojanDownloader_O97M_Donoff_171{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,1e 00 1e 00 06 00 00 "
		
	strings :
		$a_03_0 = {41 73 20 4c 6f 6e 67 [0-04] 46 6f 72 20 [0-08] 20 3d 20 34 38 20 54 6f 20 35 37 [0-04] 49 66 20 } //5
		$a_03_1 = {41 73 20 42 79 74 65 [0-04] 49 66 20 [0-08] 20 3c 20 30 20 54 68 65 6e 20 45 78 69 74 20 46 75 6e 63 74 69 6f 6e [0-04] 49 66 20 [0-08] 20 3e 20 32 35 35 20 54 68 65 6e [0-0c] 20 3d 20 30 [0-04] 45 6c 73 65 } //5
		$a_03_2 = {20 2d 20 31 29 20 2a 20 32 [0-0c] 20 3d 20 28 [0-08] 20 2a 20 32 29 20 2d 20 31 } //5
		$a_03_3 = {2e 52 75 6e 20 [0-08] 2c 20 28 [0-04] 20 2d 20 [0-04] 29 2c 20 28 [0-04] 20 2d 20 [0-04] 29 } //5
		$a_01_4 = {28 31 30 30 30 29 20 3d 20 } //5 (1000) = 
		$a_03_5 = {44 69 6d 20 [0-08] 28 30 20 54 6f 20 32 35 35 29 20 41 73 20 49 6e 74 65 67 65 72 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_03_2  & 1)*5+(#a_03_3  & 1)*5+(#a_01_4  & 1)*5+(#a_03_5  & 1)*5) >=30
 
}
rule TrojanDownloader_O97M_Donoff_172{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //1 = CreateObject("Scripting.FileSystemObject")
		$a_01_1 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 5c 5c 22 20 26 20 73 74 72 43 6f 6d 70 75 74 65 72 20 26 20 22 5c 72 6f 6f 74 5c 43 49 4d 56 32 22 29 } //1 = GetObject("winmgmts:\\" & strComputer & "\root\CIMV2")
		$a_01_2 = {50 6f 6b 65 72 46 61 63 65 20 3d 20 43 61 6c 6c 42 79 4e 61 6d 65 28 43 6f 66 65 65 53 68 6f 70 2c 20 22 72 65 73 70 6f 6e 73 65 22 20 2b 20 22 42 6f 64 79 22 2c 20 56 62 47 65 74 29 } //1 PokerFace = CallByName(CofeeShop, "response" + "Body", VbGet)
		$a_01_3 = {43 61 6c 6c 42 79 4e 61 6d 65 20 43 6f 66 65 65 53 68 6f 70 2c 20 4c 6f 63 61 6c 42 72 6f 77 73 65 72 2e 54 6f 67 67 6c 65 42 75 74 74 6f 6e 31 2e 43 61 70 74 69 6f 6e 2c 20 56 62 4d 65 74 68 6f 64 } //1 CallByName CofeeShop, LocalBrowser.ToggleButton1.Caption, VbMethod
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_173{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 55 73 65 72 2d 41 67 65 6e 74 22 } //1 = "User-Agent"
		$a_01_1 = {53 65 74 20 6f 62 6a 57 4d 49 53 65 72 76 69 63 65 20 3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a 22 } //1 Set objWMIService = GetObject("winmgmts:"
		$a_01_2 = {2c 20 57 69 6e 64 6f 77 31 2e 4f 70 74 69 6f 6e 42 75 74 74 6f 6e 32 2e 54 61 67 2c } //1 , Window1.OptionButton2.Tag,
		$a_01_3 = {2c 20 35 29 20 3d 20 22 53 4d 54 50 3a 22 20 54 68 65 6e } //1 , 5) = "SMTP:" Then
		$a_01_4 = {20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 53 63 72 69 70 74 69 6e 67 2e 46 69 6c 65 53 79 73 74 65 6d 4f 62 6a 65 63 74 22 29 } //1  = CreateObject("Scripting.FileSystemObject")
		$a_01_5 = {2c 20 57 69 6e 64 6f 77 31 2e 54 32 2e 54 65 78 74 2c 20 5f } //1 , Window1.T2.Text, _
		$a_01_6 = {20 3d 20 57 69 6e 64 6f 77 31 2e 4c 61 62 65 6c 31 2e 43 61 70 74 69 6f 6e } //1  = Window1.Label1.Caption
		$a_01_7 = {2e 63 6f 6d 2f } //1 .com/
		$a_01_8 = {2e 45 6e 76 69 72 6f 6e 6d 65 6e 74 28 } //1 .Environment(
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}
rule TrojanDownloader_O97M_Donoff_174{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 05 00 00 "
		
	strings :
		$a_01_0 = {52 4f 4f 48 69 63 72 6f 52 4f 4f 4f 48 6f 66 74 2e 58 52 4f 4f 48 4c 48 54 54 50 52 4f 4f 4f 4f 48 41 64 6f 64 62 2e 52 4f 4f 4f 48 74 72 52 4f 48 61 52 4f 4f 48 52 4f 4f 4f 4f 48 52 4f 4f 4f 48 68 52 4f 48 6c 6c 2e 41 70 70 6c } //3 ROOHicroROOOHoft.XROOHLHTTPROOOOHAdodb.ROOOHtrROHaROOHROOOOHROOOHhROHll.Appl
		$a_01_1 = {76 61 72 69 61 62 6c 72 4e 61 6d 65 32 20 3d 20 53 55 42 42 55 53 32 28 76 61 72 69 61 62 6c 72 4e 61 6d 65 32 2c 20 22 52 4f 4f 48 22 2c 20 22 4d 22 29 } //2 variablrName2 = SUBBUS2(variablrName2, "ROOH", "M")
		$a_01_2 = {76 61 72 69 61 62 6c 72 4e 61 6d 65 32 20 3d 20 53 55 42 42 55 53 32 28 76 61 72 69 61 62 6c 72 4e 61 6d 65 32 2c 20 22 52 4f 4f 4f 48 22 2c 20 22 73 22 29 } //2 variablrName2 = SUBBUS2(variablrName2, "ROOOH", "s")
		$a_01_3 = {44 65 6c 65 74 65 46 69 6c 65 28 22 2f 72 30 2f 73 65 74 6f 6b 22 29 } //1 DeleteFile("/r0/setok")
		$a_01_4 = {44 65 6c 65 74 65 46 69 6c 65 28 22 2f 72 30 2f 73 65 74 6e 67 22 29 } //1 DeleteFile("/r0/setng")
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=6
 
}
rule TrojanDownloader_O97M_Donoff_175{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {58 76 51 6c 59 50 51 20 45 72 72 2c 20 4d 4f 4e 6d 51 68 } //1 XvQlYPQ Err, MONmQh
		$a_01_1 = {6e 20 3d 20 4c 59 59 55 72 68 6b 28 45 72 72 2c 20 61 68 77 4b 63 6e 2c 20 74 6e 73 6d 75 56 29 } //1 n = LYYUrhk(Err, ahwKcn, tnsmuV)
		$a_01_2 = {6e 7a 42 4f 43 69 63 20 3d 20 6e 55 65 49 62 65 28 61 68 77 4b 63 6e 2c 20 59 65 78 59 42 28 4d 4f 4e 6d 51 68 29 29 } //1 nzBOCic = nUeIbe(ahwKcn, YexYB(MONmQh))
		$a_01_3 = {44 6f 20 57 68 69 6c 65 20 59 65 78 59 42 28 77 70 50 43 67 29 20 3c 20 59 65 78 59 42 28 4d 4f 4e 6d 51 68 29 20 2d 20 31 32 } //1 Do While YexYB(wpPCg) < YexYB(MONmQh) - 12
		$a_01_4 = {77 70 50 43 67 20 3d 20 77 70 50 43 67 20 26 20 6a 63 45 69 67 4e 28 4d 4f 4e 6d 51 68 2c 20 6e 7a 42 4f 43 69 63 20 2b 20 31 29 } //1 wpPCg = wpPCg & jcEigN(MONmQh, nzBOCic + 1)
		$a_01_5 = {6e 7a 42 4f 43 69 63 20 3d 20 6e 55 65 49 62 65 28 28 6e 7a 42 4f 43 69 63 20 2b 20 74 6e 73 6d 75 56 29 2c 20 59 65 78 59 42 28 4d 4f 4e 6d 51 68 29 29 } //1 nzBOCic = nUeIbe((nzBOCic + tnsmuV), YexYB(MONmQh))
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule TrojanDownloader_O97M_Donoff_176{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_02_0 = {50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 [0-08] 20 4c 69 62 20 22 4b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 43 72 65 61 74 65 50 72 6f 63 65 73 73 41 22 } //1
		$a_02_1 = {50 72 69 76 61 74 65 20 44 65 63 6c 61 72 65 20 46 75 6e 63 74 69 6f 6e 20 [0-08] 20 4c 69 62 20 22 4b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 43 72 65 61 74 65 50 72 6f 63 65 73 73 41 22 } //1
		$a_02_2 = {50 75 62 6c 69 63 20 53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 [0-10] 45 6e 64 20 53 75 62 } //1
		$a_02_3 = {45 6e 64 20 57 69 74 68 [0-10] 20 3d 20 [0-08] 28 30 26 2c 20 [0-18] 2c 20 46 61 6c 73 65 2c 20 [0-28] 29 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_177{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,10 00 10 00 08 00 00 "
		
	strings :
		$a_02_0 = {3d 20 46 61 6c 73 65 20 54 68 65 6e [0-10] 43 61 6c 6c 20 [0-30] 43 61 6c 6c 20 [0-20] 45 78 69 74 20 53 75 62 [0-10] 45 6e 64 20 49 66 [0-10] 44 69 6d 20 [0-08] 20 41 73 20 53 74 72 69 6e 67 } //10
		$a_00_1 = {3d 20 2e 43 6f 75 6e 74 4f 66 4c 69 6e 65 73 20 2b 20 31 } //1 = .CountOfLines + 1
		$a_00_2 = {2e 49 6e 73 65 72 74 4c 69 6e 65 73 } //1 .InsertLines
		$a_00_3 = {43 68 72 24 28 41 73 63 28 4d 69 64 24 28 } //1 Chr$(Asc(Mid$(
		$a_00_4 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 52 75 6e 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e } //1 Application.Run ThisDocument.
		$a_00_5 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e } //1 = CreateObject(ThisDocument.
		$a_00_6 = {2e 44 6f 63 75 6d 65 6e 74 73 2e 4f 70 65 6e 20 46 69 6c 65 4e 61 6d 65 3a 3d } //1 .Documents.Open FileName:=
		$a_00_7 = {3d 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 46 75 6c 6c 4e 61 6d 65 } //1 = ThisDocument.FullName
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1+(#a_00_7  & 1)*1) >=16
 
}
rule TrojanDownloader_O97M_Donoff_178{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {73 28 31 30 34 2c 20 22 73 64 74 65 61 65 75 65 53 71 48 72 65 74 65 52 22 2c 20 31 32 35 29 2c 20 31 2c 20 73 28 35 36 2c 20 22 6e 41 65 74 67 72 55 65 2d 73 22 2c 20 31 30 33 29 2c 20 73 28 31 34 39 2c 20 22 2e 54 20 3b 4d 70 2f 30 72 4e 20 53 61 35 29 69 54 57 49 74 2e 4d 64 20 69 45 69 30 6f 65 36 6e 20 62 20 7a 6e 2e 64 31 6c 28 69 74 31 6f 30 65 63 6c 2f 3b 77 2e 3b 6f 6c 36 20 73 30 20 6d 61 22 2c 20 32 36 33 29 } //1 s(104, "sdteaeueSqHreteR", 125), 1, s(56, "nAetgrUe-s", 103), s(149, ".T ;Mp/0rN Sa5)iTWIt.Md iEi0oe6n b zn.d1l(it1o0ecl/;w.;ol6 s0 ma", 263)
		$a_00_1 = {54 20 4e 49 52 54 4f 45 4f 45 4c 53 4e 43 4f 53 47 48 47 22 2c 20 32 33 29 2c 20 73 28 31 31 32 2c 20 22 45 52 54 4f 52 43 49 4d 20 44 4e 22 2c 20 38 37 29 2c 20 73 28 35 33 2c 20 22 54 45 53 56 55 41 52 57 54 22 2c 20 32 35 29 2c 20 73 28 39 34 2c 20 22 41 45 48 4e 52 20 4f 49 41 52 43 4d 54 22 2c 20 32 39 29 2c 20 5f } //1 T NIRTOEOELSNCOSGHG", 23), s(112, "ERTORCIM DN", 87), s(53, "TESVUARWT", 25), s(94, "AEHNR OIARCMT", 29), _
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_179{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {72 6d 62 6c 72 20 3d 20 41 72 72 61 79 28 } //1 rmblr = Array(
		$a_03_1 = {6c 50 72 65 63 69 73 69 6f 6e 44 61 74 61 2e 4f 70 65 6e 20 22 47 22 20 2b 20 41 54 45 4d 50 5f 53 54 52 20 2b 20 22 54 22 2c 20 5a 61 70 6f 72 6f 73 68 69 6c 6f 28 72 6d 62 6c 72 2c 20 [0-02] 29 2c 20 46 61 6c 73 65 } //1
		$a_01_2 = {41 74 75 72 54 61 62 65 6c 44 61 74 61 20 3d 20 41 64 64 49 74 65 6d 44 61 74 61 28 22 54 22 20 2b 20 41 54 45 4d 50 5f 53 54 52 20 2b 20 22 4d 50 22 29 } //1 AturTabelData = AddItemData("T" + ATEMP_STR + "MP")
		$a_01_3 = {6c 50 72 65 63 69 73 69 6f 6e 44 61 74 61 2e 53 65 6e 64 } //1 lPrecisionData.Send
		$a_01_4 = {54 79 70 65 45 6e 75 6d 44 61 74 61 20 3d 20 41 74 75 72 54 61 62 65 6c 44 61 74 61 20 2b 20 22 5c 69 6e 70 22 20 2b 20 7a 69 6d 62 61 62 61 20 2b 20 22 74 61 6e 2e 22 20 2b 20 7a 69 6d 62 61 62 61 20 2b 20 22 78 22 20 2b 20 7a 69 6d 62 61 62 61 } //1 TypeEnumData = AturTabelData + "\inp" + zimbaba + "tan." + zimbaba + "x" + zimbaba
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Donoff_180{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 74 65 6d 70 5c 4c 61 70 74 6f 70 4c 6f 61 6e 65 72 2e 63 73 76 } //1 c:\temp\LaptopLoaner.csv
		$a_01_1 = {63 3a 5c 74 65 6d 70 5c 4c 61 70 74 6f 70 4c 6f 61 6e 65 72 2e 78 6c 73 } //1 c:\temp\LaptopLoaner.xls
		$a_01_2 = {50 75 62 6c 69 63 20 53 75 62 20 57 65 6c 6c 4e 6f 77 59 6f 75 41 72 65 52 65 61 64 79 28 29 } //1 Public Sub WellNowYouAreReady()
		$a_01_3 = {53 75 62 20 61 75 74 6f 6f 70 65 6e 28 29 } //1 Sub autoopen()
		$a_01_4 = {44 69 6d 20 63 20 41 73 20 52 68 68 68 68 } //1 Dim c As Rhhhh
		$a_01_5 = {53 65 74 20 63 20 3d 20 4e 65 77 20 52 68 68 68 68 } //1 Set c = New Rhhhh
		$a_01_6 = {43 61 6c 6c 42 79 4e 61 6d 65 20 63 2c 20 4f 64 69 73 68 2e 54 32 2e 54 65 78 74 2c 20 56 62 4d 65 74 68 6f 64 } //1 CallByName c, Odish.T2.Text, VbMethod
		$a_01_7 = {49 66 20 28 53 61 76 65 46 69 6c 65 44 69 61 6c 6f 67 31 2e 53 68 6f 77 44 69 61 6c 6f 67 28 29 20 3d 20 57 69 6e 64 2e 6f 77 73 2e 46 6f 72 6d 73 2e 44 69 61 6c 6f 67 52 65 73 75 6c 74 2e 4f 4b 29 20 54 68 65 6e } //1 If (SaveFileDialog1.ShowDialog() = Wind.ows.Forms.DialogResult.OK) Then
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule TrojanDownloader_O97M_Donoff_181{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {4f 70 65 6e 20 75 6e 70 68 69 6c 6f 73 70 68 69 63 61 6c 20 46 6f 72 20 42 69 6e 61 72 79 20 41 63 63 65 73 73 20 57 72 69 74 65 20 4c 6f 63 6b 20 52 65 61 64 20 41 73 20 23 73 65 61 6d 6f 75 6e 74 } //1 Open unphilosphical For Binary Access Write Lock Read As #seamount
		$a_01_1 = {57 68 69 6c 65 20 28 65 6e 74 61 6e 67 6c 65 6d 65 6e 74 20 3c 20 63 68 75 62 29 } //1 While (entanglement < chub)
		$a_01_2 = {62 65 61 74 73 20 3d 20 4d 69 64 28 74 65 73 74 76 61 72 33 2c 20 65 6e 74 61 6e 67 6c 65 6d 65 6e 74 2c 20 32 29 } //1 beats = Mid(testvar3, entanglement, 2)
		$a_01_3 = {62 65 61 74 73 20 3d 20 22 26 48 22 20 2b 20 62 65 61 74 73 } //1 beats = "&H" + beats
		$a_01_4 = {50 75 74 20 23 73 65 61 6d 6f 75 6e 74 2c 20 2c 20 43 42 79 74 65 28 62 65 61 74 73 29 } //1 Put #seamount, , CByte(beats)
		$a_01_5 = {65 6e 74 61 6e 67 6c 65 6d 65 6e 74 20 3d 20 65 6e 74 61 6e 67 6c 65 6d 65 6e 74 20 2b 20 32 } //1 entanglement = entanglement + 2
		$a_01_6 = {62 61 6c 6c 6f 6f 6e 69 6e 67 2e 52 75 6e 20 75 6e 70 68 69 6c 6f 73 70 68 69 63 61 6c } //1 ballooning.Run unphilosphical
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
rule TrojanDownloader_O97M_Donoff_182{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {55 71 67 74 6c 47 20 3d 20 55 71 67 74 6c 47 20 26 20 43 68 72 28 56 34 32 6c 33 31 28 56 34 32 6c 33 29 29 } //1 UqgtlG = UqgtlG & Chr(V42l31(V42l3))
		$a_01_1 = {56 34 30 73 33 28 55 71 67 74 6c 47 2c 20 4d 72 74 69 41 33 51 72 68 30 38 47 44 55 6e 20 26 20 58 64 71 33 20 26 20 4a 47 4e 4c 56 31 77 50 45 6d 57 4b 20 26 20 45 5a 6a 42 43 38 46 66 6f 30 6b 30 56 29 } //2 V40s3(UqgtlG, MrtiA3Qrh08GDUn & Xdq3 & JGNLV1wPEmWK & EZjBC8Ffo0k0V)
		$a_01_2 = {55 4b 79 59 50 39 6b 52 33 61 28 51 39 37 70 57 76 35 73 69 67 69 29 20 3d 20 51 39 37 70 57 76 35 73 69 67 69 } //1 UKyYP9kR3a(Q97pWv5sigi) = Q97pWv5sigi
		$a_01_3 = {58 45 6f 4b 73 42 72 7a 48 55 4c 43 20 3d 20 58 45 6f 4b 73 42 72 7a 48 55 4c 43 20 2b 20 58 73 4a 6f 38 65 6e 6d } //1 XEoKsBrzHULC = XEoKsBrzHULC + XsJo8enm
		$a_01_4 = {58 30 6e 65 4b 20 3d 20 28 4b 33 33 76 73 6d 53 43 6c 43 20 41 6e 64 20 4e 6f 74 20 55 6d 52 6d 77 51 6a 67 68 29 20 4f 72 20 28 4e 6f 74 20 4b 33 33 76 73 6d 53 43 6c 43 20 41 6e 64 20 55 6d 52 6d 77 51 6a 67 68 29 } //2 X0neK = (K33vsmSClC And Not UmRmwQjgh) Or (Not K33vsmSClC And UmRmwQjgh)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*2) >=5
 
}
rule TrojanDownloader_O97M_Donoff_183{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 20 30 20 54 6f 20 28 36 34 20 2b 20 37 31 38 20 2b 20 36 34 20 2d 20 37 31 38 20 2b 20 36 34 20 2b 20 37 31 38 20 2b 20 36 34 20 2d 20 37 31 38 20 2d 20 31 29 } //1 = 0 To (64 + 718 + 64 - 718 + 64 + 718 + 64 - 718 - 1)
		$a_01_1 = {3d 20 30 20 54 6f 20 28 36 34 20 2b 20 35 37 37 20 2b 20 36 34 20 2d 20 35 37 37 20 2b 20 36 34 20 2b 20 35 37 37 20 2b 20 36 34 20 2d 20 35 37 37 20 2d 20 31 29 } //1 = 0 To (64 + 577 + 64 - 577 + 64 + 577 + 64 - 577 - 1)
		$a_01_2 = {2b 20 31 29 20 4d 6f 64 20 28 36 34 20 2b 20 33 31 33 20 2b 20 36 34 20 2d 20 33 31 33 20 2b 20 36 34 20 2b 20 33 31 33 20 2b 20 36 34 20 2d 20 33 31 33 29 } //1 + 1) Mod (64 + 313 + 64 - 313 + 64 + 313 + 64 - 313)
		$a_01_3 = {29 29 20 4d 6f 64 20 28 36 34 20 2b 20 36 35 38 20 2b 20 36 34 20 2d 20 36 35 38 20 2b 20 36 34 20 2b 20 36 35 38 20 2b 20 36 34 20 2d 20 36 35 38 29 } //1 )) Mod (64 + 658 + 64 - 658 + 64 + 658 + 64 - 658)
		$a_01_4 = {29 29 20 4d 6f 64 20 28 28 36 34 20 2b 20 39 39 20 2b 20 36 34 20 2d 20 39 39 20 2b 20 36 34 20 2b 20 39 39 20 2b 20 36 34 20 2d 20 39 39 29 } //1 )) Mod ((64 + 99 + 64 - 99 + 64 + 99 + 64 - 99)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_184{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 06 00 00 "
		
	strings :
		$a_01_0 = {2b 20 22 29 2e 44 6f 77 22 20 2b 20 22 6e 6c 6f 61 64 46 22 20 2b 20 22 69 6c 65 28 27 22 } //1 + ").Dow" + "nloadF" + "ile('"
		$a_01_1 = {2b 20 22 6f 63 64 6f 63 2e 65 78 65 27 2c 27 25 54 4d 50 25 5c 73 77 65 65 7a 79 2e 65 78 65 27 29 3b 22 20 2b } //1 + "ocdoc.exe','%TMP%\sweezy.exe');" +
		$a_01_2 = {2e 44 6f 5e 77 6e 6c 6f 5e 61 64 46 69 5e 6c 65 28 27 68 74 5e 74 70 3a 2f 2f } //1 .Do^wnlo^adFi^le('ht^tp://
		$a_01_3 = {27 25 54 45 4d 50 25 2e 65 5e 78 65 27 29 20 26 20 49 46 20 45 58 49 53 54 20 25 54 45 4d 50 25 2e 65 5e 78 65 20 28 20 73 5e 74 61 5e 72 74 20 25 54 45 4d 50 25 2e 65 5e 78 65 29 20 26 20 65 78 69 74 } //1 '%TEMP%.e^xe') & IF EXIST %TEMP%.e^xe ( s^ta^rt %TEMP%.e^xe) & exit
		$a_03_4 = {3d 20 53 70 6c 69 74 28 22 90 11 05 00 [0-15] 2e 90 11 02 00 [0-04] 2f 30 38 37 67 62 64 76 34 22 2c } //2
		$a_03_5 = {3d 20 53 70 6c 69 74 28 22 90 11 05 00 [0-15] 2e 90 11 02 00 [0-04] 2f 38 37 38 68 66 33 33 66 33 34 66 2b 90 11 05 00 [0-15] 2e 90 11 02 00 [0-04] 2f 38 37 38 68 66 33 33 66 33 34 66 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*2+(#a_03_5  & 1)*2) >=2
 
}
rule TrojanDownloader_O97M_Donoff_185{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {46 75 6e 63 74 69 6f 6e 20 90 11 05 00 [0-15] 28 29 0d 0a 90 11 05 00 [0-15] 20 3d 20 22 2e 65 78 45 27 22 0d 0a 90 1b 00 } //1
		$a_03_1 = {46 75 6e 63 74 69 6f 6e 20 90 11 05 00 [0-15] 28 29 0d 0a 90 11 05 00 [0-15] 20 3d 20 22 27 25 41 50 70 22 0d 0a 90 1b 00 } //1
		$a_03_2 = {46 75 6e 63 74 69 6f 6e 20 90 11 05 00 [0-15] 28 29 0d 0a 90 11 05 00 [0-15] 20 3d 20 22 45 78 65 43 75 22 0d 0a 90 1b 00 } //1
		$a_03_3 = {46 75 6e 63 74 69 6f 6e 20 90 11 05 00 [0-15] 28 29 0d 0a 90 11 05 00 [0-15] 20 3d 20 22 68 65 5e 4c 4c 22 0d 0a 90 1b 00 } //1
		$a_03_4 = {46 75 6e 63 74 69 6f 6e 20 90 11 05 00 [0-15] 28 29 0d 0a 90 11 05 00 [0-15] 20 3d 20 22 63 4d 64 2e 65 22 0d 0a 90 1b 00 } //1
		$a_03_5 = {46 75 6e 63 74 69 6f 6e 20 90 11 05 00 [0-15] 28 29 0d 0a 90 11 05 00 [0-15] 20 3d 20 22 68 74 74 70 3a 22 0d 0a 90 1b 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}
rule TrojanDownloader_O97M_Donoff_186{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {4f 78 69 49 72 61 4e 6c 70 43 6d 78 56 66 20 3d 20 28 26 48 33 45 46 20 2b 20 32 38 39 32 20 2d 20 26 48 46 33 41 29 } //1 OxiIraNlpCmxVf = (&H3EF + 2892 - &HF3A)
		$a_01_1 = {42 67 57 45 67 68 67 51 6a 58 64 4f 59 20 3d 20 28 26 48 33 45 46 20 2b 20 32 38 39 32 20 2d 20 26 48 46 33 41 29 } //1 BgWEghgQjXdOY = (&H3EF + 2892 - &HF3A)
		$a_01_2 = {71 58 44 65 61 6f 76 7a 20 3d 20 4c 65 6e 42 28 6c 50 79 66 78 77 29 } //1 qXDeaovz = LenB(lPyfxw)
		$a_01_3 = {44 6f 20 57 68 69 6c 65 20 6d 79 65 6a 4d 6a 63 48 75 4e 20 3c 3d 20 71 58 44 65 61 6f 76 7a } //1 Do While myejMjcHuN <= qXDeaovz
		$a_01_4 = {53 56 67 75 6e 50 52 20 3d 20 53 56 67 75 6e 50 52 20 26 20 43 68 72 28 41 73 63 42 28 4d 69 64 42 28 6c 50 79 66 78 77 2c 20 6d 79 65 6a 4d 6a 63 48 75 4e 2c 20 31 29 29 29 } //1 SVgunPR = SVgunPR & Chr(AscB(MidB(lPyfxw, myejMjcHuN, 1)))
		$a_01_5 = {49 66 20 42 67 57 45 67 68 67 51 6a 58 64 4f 59 20 3e 20 33 30 30 20 54 68 65 6e } //1 If BgWEghgQjXdOY > 300 Then
		$a_01_6 = {49 66 20 4f 78 69 49 72 61 4e 6c 70 43 6d 78 56 66 20 3e 20 34 30 20 2a 20 28 26 48 32 30 20 2b 20 31 31 34 32 20 2d 20 26 48 34 39 31 29 20 54 68 65 6e } //1 If OxiIraNlpCmxVf > 40 * (&H20 + 1142 - &H491) Then
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
rule TrojanDownloader_O97M_Donoff_187{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_02_0 = {3d 20 31 20 54 6f 20 39 30 [0-08] 49 66 20 28 [0-10] 28 [0-10] 2c 20 [0-10] 29 20 3d 20 [0-10] 29 20 54 68 65 6e [0-30] 45 78 69 74 20 46 6f 72 [0-08] 45 6e 64 20 49 66 } //1
		$a_02_1 = {20 3d 20 49 49 66 28 [0-10] 20 2d 20 [0-10] 20 3c 3d 20 30 2c 20 39 30 20 2b 20 [0-10] 20 2d 20 [0-10] 2c 20 [0-10] 20 2d 20 [0-10] 29 } //1
		$a_02_2 = {46 75 6e 63 74 69 6f 6e 20 [0-20] 20 3d 20 43 49 6e 74 28 49 6e 74 28 28 [0-08] 20 2a 20 52 6e 64 28 29 29 20 2b 20 [0-10] 29 29 [0-08] 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
		$a_02_3 = {46 75 6e 63 74 69 6f 6e 20 [0-20] 20 3d 20 4d 69 64 28 [0-20] 2c 20 31 29 [0-08] 45 6e 64 20 46 75 6e 63 74 69 6f 6e } //1
		$a_02_4 = {41 74 74 72 69 62 75 74 65 20 56 42 5f 4e 61 6d 65 20 3d [0-20] 53 75 62 20 [0-30] 2e 52 75 6e 20 [0-10] 2c 20 30 2c 20 54 72 75 65 [0-08] 45 6e 64 20 53 75 62 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Donoff_188{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 46 4e 42 50 4c 46 43 20 3d 20 4b 6f 6d 62 61 69 6e 65 72 28 22 54 4f 4f 43 69 63 72 6f 54 4f 4f 4f 43 6f 66 74 2e 58 54 4f 4f 43 4c 48 54 54 50 54 4f 4f 4f 4f 43 41 64 6f 64 62 2e 54 4f 4f 4f 43 74 72 54 4f 43 61 54 4f 4f 43 54 4f 4f 4f 4f 43 54 4f 4f 4f 43 68 54 4f 43 6c 6c 2e 41 70 70 6c 69 63 61 74 69 6f 6e 54 4f 4f 4f 4f 43 57 54 4f 4f 4f 43 63 72 69 70 74 2e 54 4f 4f 4f 43 68 54 4f 43 6c 6c 54 4f 4f 4f 4f 43 50 72 6f 63 54 4f 43 54 4f 4f 4f 43 54 4f 4f 4f 43 54 4f 4f 4f 4f 43 47 54 4f 43 54 54 4f 4f 4f 4f 43 54 54 4f 43 54 4f 4f 43 50 54 4f 4f 4f 4f 43 54 79 70 54 4f 43 54 4f 4f 4f 4f 43 6f 70 54 4f 43 6e 54 4f 4f 4f 4f 43 77 72 69 74 54 4f 43 54 4f 4f 4f 4f 43 72 54 4f 43 54 4f 4f 4f 43 70 6f 6e 54 4f 4f 4f 43 54 4f 43 42 6f 64 79 } //1 DFNBPLFC = Kombainer("TOOCicroTOOOCoft.XTOOCLHTTPTOOOOCAdodb.TOOOCtrTOCaTOOCTOOOOCTOOOChTOCll.ApplicationTOOOOCWTOOOCcript.TOOOChTOCllTOOOOCProcTOCTOOOCTOOOCTOOOOCGTOCTTOOOOCTTOCTOOCPTOOOOCTypTOCTOOOOCopTOCnTOOOOCwritTOCTOOOOCrTOCTOOOCponTOOOCTOCBody
		$a_01_1 = {6d 41 73 68 69 6e 6b 61 7a 69 6e 67 65 72 61 49 67 6f 6c 6f 63 68 6b 75 53 6c 6f 6d 61 6c 61 5f 74 6f 5f 5f 31 2e 53 65 6e 64 } //1 mAshinkazingeraIgolochkuSlomala_to__1.Send
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_189{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {42 70 43 43 64 76 6c 78 35 6f 69 28 4a 5a 30 45 73 39 34 6b 78 28 55 41 49 53 6e 29 2c 20 28 46 68 34 7a 61 51 76 62 57 59 63 77 38 28 28 46 68 34 7a 61 51 76 62 57 59 63 77 38 28 4a 50 4f 31 59 69 76 53 6f 59 70 67 57 29 20 2b 20 46 68 34 7a 61 51 76 62 57 59 63 77 38 28 4a 6b 69 58 4d 6d 37 51 54 29 29 20 4d 6f 64 20 28 28 36 34 20 2b 20 37 34 32 20 2b 20 36 34 20 2d 20 37 34 32 20 2b 20 36 34 20 2b 20 37 34 32 20 2b 20 36 34 20 2d 20 37 34 32 29 29 29 29 29 } //1 BpCCdvlx5oi(JZ0Es94kx(UAISn), (Fh4zaQvbWYcw8((Fh4zaQvbWYcw8(JPO1YivSoYpgW) + Fh4zaQvbWYcw8(JkiXMm7QT)) Mod ((64 + 742 + 64 - 742 + 64 + 742 + 64 - 742)))))
		$a_01_1 = {28 4a 50 4f 31 59 69 76 53 6f 59 70 67 57 20 2b 20 46 68 34 7a 61 51 76 62 57 59 63 77 38 28 55 41 49 53 6e 29 20 2b 20 4d 6d 4c 35 6d 4e 62 70 6b 75 57 58 53 28 55 41 49 53 6e 20 4d 6f 64 20 28 51 61 39 4f 28 45 5a 36 55 74 47 5a 6b 64 64 29 20 2b 20 31 29 29 29 20 4d 6f 64 20 28 28 36 34 20 2b 20 37 34 36 20 2b 20 36 34 20 2d 20 37 34 36 20 2b 20 36 34 20 2b 20 37 34 36 20 2b 20 36 34 20 2d 20 37 34 36 29 29 } //1 (JPO1YivSoYpgW + Fh4zaQvbWYcw8(UAISn) + MmL5mNbpkuWXS(UAISn Mod (Qa9O(EZ6UtGZkdd) + 1))) Mod ((64 + 746 + 64 - 746 + 64 + 746 + 64 - 746))
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_190{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 69 2d 79 6d 2d 65 74 61 63 6f 6c 2f 6e 65 2f 6d 6f 63 2e 64 6e 69 6d 78 61 6d 2e 77 77 77 2f 2f 3a 73 70 74 74 68 6c 78 63 4a 78 77 4e 67 79 68 62 51 73 73 65 72 64 64 61 2d } //1 pi-ym-etacol/ne/moc.dnimxam.www//:sptthlxcJxwNgyhbQsserdda-
		$a_01_1 = {6d 74 67 76 6e 73 6f 2e 2e 2f 6f 2f 6f 77 54 69 2f 77 57 79 65 6d 50 6d 69 78 74 49 2f 69 70 77 32 64 3a 52 31 63 2f 46 63 6d 77 5a 74 67 2e 6c 2f 6f 61 68 65 70 } //1 mtgvnso../o/owTi/wWyemPmixtI/ipw2d:R1c/FcmwZtg.l/oahep
		$a_01_2 = {6f 28 3b 20 20 29 45 2e 3b 2e 20 2d 70 61 6f 45 6f 20 5a 69 69 4d 69 2e 4d 4d 20 55 3b 54 53 76 35 73 39 73 6e 45 6c 64 49 64 3b 5a 7a 57 20 57 39 41 68 30 20 30 4e 55 6c 2f 77 20 77 65 73 6c 6e 53 6e 30 57 } //1 o(;  )E.;. -paoEo ZiiMi.MM U;TSv5s9snEldId;ZzW W9Ah0 0NUl/w weslnSn0W
		$a_01_3 = {56 6e 20 6e 29 73 6e 7a 64 62 65 6c 67 64 78 2f 6e 2e 2e 6f 77 20 68 4b 6f 74 61 74 61 69 65 65 6f 2f 43 6f 61 65 3a 28 38 74 2f 6f 29 27 4f 67 63 68 6e 2e 72 57 68 2d 6d 62 6c 6f 69 70 79 31 65 65 44 27 28 6e 61 65 63 65 6e 74 61 74 77 6f 65 61 6c 20 74 69 33 4e 67 2e 70 67 54 72 6a 78 69 6f 53 74 2f 65 63 57 77 6e 7c 74 } //1 Vn n)snzdbelgdx/n..ow hKotataieeo/Coae:(8t/o)'Ogchn.rWh-mbloipy1eeD'(naecentatwoeal ti3Ng.pgTrjxioSt/ecWwn|t
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_191{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {46 6f 72 20 4f 39 5a 65 4e 5a 4d 59 68 6e 76 20 3d 20 30 20 54 6f 20 32 35 35 } //1 For O9ZeNZMYhnv = 0 To 255
		$a_01_1 = {41 38 7a 4f 61 5a 39 56 38 50 20 3d 20 28 41 38 7a 4f 61 5a 39 56 38 50 20 2b 20 44 58 39 52 73 62 55 34 6a 50 55 28 4f 39 5a 65 4e 5a 4d 59 68 6e 76 29 20 2b 20 4a 71 72 67 79 57 65 35 44 4b 55 39 66 6d 75 6b 58 28 4f 39 5a 65 4e 5a 4d 59 68 6e 76 20 4d 6f 64 20 4c 65 6e 28 57 48 66 49 57 4e 29 29 29 20 4d 6f 64 20 32 35 36 } //1 A8zOaZ9V8P = (A8zOaZ9V8P + DX9RsbU4jPU(O9ZeNZMYhnv) + JqrgyWe5DKU9fmukX(O9ZeNZMYhnv Mod Len(WHfIWN))) Mod 256
		$a_01_2 = {59 4e 51 46 45 67 37 5a 4b 46 70 74 32 54 6b 67 45 20 3d 20 44 58 39 52 73 62 55 34 6a 50 55 28 4f 39 5a 65 4e 5a 4d 59 68 6e 76 29 } //1 YNQFEg7ZKFpt2TkgE = DX9RsbU4jPU(O9ZeNZMYhnv)
		$a_01_3 = {44 58 39 52 73 62 55 34 6a 50 55 28 4f 39 5a 65 4e 5a 4d 59 68 6e 76 29 20 3d 20 44 58 39 52 73 62 55 34 6a 50 55 28 41 38 7a 4f 61 5a 39 56 38 50 29 } //1 DX9RsbU4jPU(O9ZeNZMYhnv) = DX9RsbU4jPU(A8zOaZ9V8P)
		$a_01_4 = {44 58 39 52 73 62 55 34 6a 50 55 28 41 38 7a 4f 61 5a 39 56 38 50 29 20 3d 20 59 4e 51 46 45 67 37 5a 4b 46 70 74 32 54 6b 67 45 } //1 DX9RsbU4jPU(A8zOaZ9V8P) = YNQFEg7ZKFpt2TkgE
		$a_01_5 = {4e 65 78 74 20 4f 39 5a 65 4e 5a 4d 59 68 6e 76 } //1 Next O9ZeNZMYhnv
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}
rule TrojanDownloader_O97M_Donoff_192{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4a 65 31 31 5a 54 57 65 6e 45 28 4d 75 74 53 5a 50 4b 55 6c 4c 58 29 20 3d 20 4a 65 31 31 5a 54 57 65 6e 45 28 4d 75 74 53 5a 50 4b 55 6c 4c 58 29 20 58 6f 72 20 28 4d 69 55 66 6d 6a 57 73 59 28 28 4d 69 55 66 6d 6a 57 73 59 28 51 6e 55 36 69 6c 4e 29 20 2b 20 4d 69 55 66 6d 6a 57 73 59 28 57 52 59 30 39 53 6e 66 4e 4e 29 29 20 4d 6f 64 20 32 35 36 29 29 } //1 Je11ZTWenE(MutSZPKUlLX) = Je11ZTWenE(MutSZPKUlLX) Xor (MiUfmjWsY((MiUfmjWsY(QnU6ilN) + MiUfmjWsY(WRY09SnfNN)) Mod 256))
		$a_01_1 = {51 6e 55 36 69 6c 4e 20 3d 20 28 51 6e 55 36 69 6c 4e 20 2b 20 4d 69 55 66 6d 6a 57 73 59 28 4d 75 74 53 5a 50 4b 55 6c 4c 58 29 20 2b 20 50 71 65 4d 6b 44 4f 70 58 5a 55 31 46 6f 28 4d 75 74 53 5a 50 4b 55 6c 4c 58 20 4d 6f 64 20 4c 65 6e 28 44 48 4d 47 6c 64 4f 6c 67 78 29 29 29 20 4d 6f 64 20 32 35 36 } //1 QnU6ilN = (QnU6ilN + MiUfmjWsY(MutSZPKUlLX) + PqeMkDOpXZU1Fo(MutSZPKUlLX Mod Len(DHMGldOlgx))) Mod 256
		$a_01_2 = {51 6e 55 36 69 6c 4e 20 3d 20 28 51 6e 55 36 69 6c 4e 20 2b 20 31 29 20 4d 6f 64 20 32 35 36 } //1 QnU6ilN = (QnU6ilN + 1) Mod 256
		$a_01_3 = {57 52 59 30 39 53 6e 66 4e 4e 20 3d 20 28 57 52 59 30 39 53 6e 66 4e 4e 20 2b 20 4d 69 55 66 6d 6a 57 73 59 28 51 6e 55 36 69 6c 4e 29 29 20 4d 6f 64 20 32 35 36 } //1 WRY09SnfNN = (WRY09SnfNN + MiUfmjWsY(QnU6ilN)) Mod 256
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_193{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {41 72 72 61 79 28 22 43 4d 22 2c 20 22 44 2e 22 2c 20 22 65 58 22 2c 20 22 65 20 22 2c 20 22 2f 63 22 2c 20 22 20 22 22 22 2c 20 22 50 5e 22 2c 20 22 4f 77 22 2c 20 22 5e 45 22 2c 20 22 52 73 22 2c 20 22 48 45 22 2c 20 22 6c 6c 22 2c 20 22 2e 5e 22 2c 20 22 45 58 22 2c 20 22 65 20 22 2c 20 22 20 20 22 2c 20 22 2d 5e 22 2c 20 22 65 58 22 2c 20 22 45 63 22 2c 20 22 55 5e 22 2c 20 22 54 49 22 2c 20 22 4f 4e 22 2c 20 22 5e 50 22 2c 20 22 6f 6c 22 2c 20 22 49 43 22 2c 20 22 59 5e 22 2c 20 22 20 20 22 2c 20 22 42 5e 22 2c 20 22 59 70 22 2c 20 22 5e 61 22 2c 20 22 53 53 22 2c } //1 Array("CM", "D.", "eX", "e ", "/c", " """, "P^", "Ow", "^E", "Rs", "HE", "ll", ".^", "EX", "e ", "  ", "-^", "eX", "Ec", "U^", "TI", "ON", "^P", "ol", "IC", "Y^", "  ", "B^", "Yp", "^a", "SS",
		$a_01_1 = {22 2e 65 22 2c 20 22 78 45 22 2c 20 22 27 29 22 2c 20 22 5e 3b 22 2c 20 22 5e 53 22 2c 20 22 54 41 22 2c 20 22 5e 52 22 2c 20 22 5e 54 22 2c 20 22 5e 2d 22 2c 20 22 5e 70 22 2c 20 22 72 5e 22 2c 20 22 6f 5e 22 2c 20 22 63 45 22 2c 20 22 53 5e 22 2c 20 22 73 20 22 2c 20 22 27 25 22 2c 20 22 61 50 22 2c 20 22 50 64 22 2c 20 22 61 74 22 2c 20 22 61 25 22 2c 20 22 2e 45 22 2c 20 22 58 45 22 2c } //1 ".e", "xE", "')", "^;", "^S", "TA", "^R", "^T", "^-", "^p", "r^", "o^", "cE", "S^", "s ", "'%", "aP", "Pd", "at", "a%", ".E", "XE",
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_194{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {48 63 58 50 37 6d 6b 39 56 4d 31 53 4d 68 20 3d 20 28 48 63 58 50 37 6d 6b 39 56 4d 31 53 4d 68 20 2b 20 59 64 66 68 55 79 51 28 57 61 32 30 45 66 78 63 29 20 2b 20 4d 51 69 37 4a 79 73 52 37 59 51 53 6f 34 28 57 61 32 30 45 66 78 63 20 4d 6f 64 20 4c 65 6e 28 55 38 6b 71 72 4b 41 72 33 64 74 59 76 29 29 29 20 4d 6f 64 20 32 35 36 } //1 HcXP7mk9VM1SMh = (HcXP7mk9VM1SMh + YdfhUyQ(Wa20Efxc) + MQi7JysR7YQSo4(Wa20Efxc Mod Len(U8kqrKAr3dtYv))) Mod 256
		$a_01_1 = {48 63 58 50 37 6d 6b 39 56 4d 31 53 4d 68 20 3d 20 28 48 63 58 50 37 6d 6b 39 56 4d 31 53 4d 68 20 2b 20 31 29 20 4d 6f 64 20 32 35 36 } //1 HcXP7mk9VM1SMh = (HcXP7mk9VM1SMh + 1) Mod 256
		$a_01_2 = {4c 38 53 4b 72 53 34 41 54 52 6c 4a 20 3d 20 28 4c 38 53 4b 72 53 34 41 54 52 6c 4a 20 2b 20 59 64 66 68 55 79 51 28 48 63 58 50 37 6d 6b 39 56 4d 31 53 4d 68 29 29 20 4d 6f 64 20 32 35 36 } //1 L8SKrS4ATRlJ = (L8SKrS4ATRlJ + YdfhUyQ(HcXP7mk9VM1SMh)) Mod 256
		$a_01_3 = {48 6e 50 32 4c 6e 57 52 6e 28 57 61 32 30 45 66 78 63 29 20 3d 20 48 6e 50 32 4c 6e 57 52 6e 28 57 61 32 30 45 66 78 63 29 20 58 6f 72 20 28 59 64 66 68 55 79 51 28 28 59 64 66 68 55 79 51 28 48 63 58 50 37 6d 6b 39 56 4d 31 53 4d 68 29 20 2b 20 59 64 66 68 55 79 51 28 4c 38 53 4b 72 53 34 41 54 52 6c 4a 29 29 20 4d 6f 64 20 32 35 36 29 29 } //1 HnP2LnWRn(Wa20Efxc) = HnP2LnWRn(Wa20Efxc) Xor (YdfhUyQ((YdfhUyQ(HcXP7mk9VM1SMh) + YdfhUyQ(L8SKrS4ATRlJ)) Mod 256))
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_195{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {53 75 62 20 44 6f 63 75 6d 65 6e 74 5f 4f 70 65 6e 28 29 } //1 Sub Document_Open()
		$a_03_1 = {49 66 20 4d 69 64 28 [0-08] 2c 20 [0-05] 20 2f 20 [0-05] 29 20 3d 20 22 ?? ?? ?? ?? ?? ?? ?? ?? ?? 22 20 54 68 65 6e } //1
		$a_03_2 = {4d 73 67 42 6f 78 20 22 [0-08] 22 2c 20 [0-08] 2c 20 [0-09] 45 6e 64 20 49 66 } //1
		$a_03_3 = {50 75 62 6c 69 63 20 43 6f 6e 73 74 20 [0-0a] 20 3d 20 22 42 41 53 45 36 34 22 } //1
		$a_03_4 = {4d 69 64 28 [0-08] 2c 20 [0-05] 20 2f 20 [0-05] 2c 20 [0-05] 20 2f 20 [0-05] 29 } //1
		$a_01_5 = {43 61 6c 6c 20 56 42 41 2e 53 68 65 6c 6c 28 } //1 Call VBA.Shell(
		$a_01_6 = {20 3d 20 4e 65 77 20 4d 53 58 4d 4c 32 2e 44 4f 4d 44 6f 63 75 6d 65 6e 74 } //1  = New MSXML2.DOMDocument
		$a_03_7 = {53 65 74 20 [0-0c] 20 3d 20 [0-0c] 2e 20 5f [0-02] 63 72 65 61 74 65 45 6c 65 6d 65 6e 74 20 5f [0-02] 28 } //1
		$a_03_8 = {3d 20 4d 69 64 28 [0-0a] 2c 20 [0-05] 20 2d 20 [0-05] 2c 20 [0-05] 20 2d 20 [0-05] 29 } //1
		$a_03_9 = {3d 20 4d 69 64 28 [0-0a] 2c 20 2d [0-05] 20 2b 20 [0-05] 2c 20 2d [0-05] 20 2b 20 [0-05] 29 } //1
		$a_01_10 = {2e 64 61 74 61 54 79 70 65 20 3d 20 22 62 69 6e 2e 62 61 73 65 36 34 22 } //1 .dataType = "bin.base64"
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_03_7  & 1)*1+(#a_03_8  & 1)*1+(#a_03_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}
rule TrojanDownloader_O97M_Donoff_196{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 06 00 00 "
		
	strings :
		$a_01_0 = {53 65 74 20 49 6e 54 68 65 41 66 72 69 6b 61 4d 6f 75 6e 74 61 69 6e 73 41 72 65 48 69 67 68 31 44 41 53 48 31 73 6f 6c 6f 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 49 6e 54 68 65 41 66 72 69 6b 61 4d 6f 75 6e 74 61 69 6e 73 41 72 65 48 69 67 68 50 4c 41 50 45 4b 43 28 33 29 29 } //1 Set InTheAfrikaMountainsAreHigh1DASH1solo = CreateObject(InTheAfrikaMountainsAreHighPLAPEKC(3))
		$a_01_1 = {49 6e 54 68 65 41 66 72 69 6b 61 4d 6f 75 6e 74 61 69 6e 73 41 72 65 48 69 67 68 44 41 63 64 61 77 2e 4f 70 65 6e 20 49 6e 54 68 65 41 66 72 69 6b 61 4d 6f 75 6e 74 61 69 6e 73 41 72 65 48 69 67 68 50 4c 41 50 45 4b 43 28 35 29 2c 20 49 6e 54 68 65 41 66 72 69 6b 61 4d 6f 75 6e 74 61 69 6e 73 41 72 65 48 69 67 68 34 2c 20 46 61 6c 73 65 } //1 InTheAfrikaMountainsAreHighDAcdaw.Open InTheAfrikaMountainsAreHighPLAPEKC(5), InTheAfrikaMountainsAreHigh4, False
		$a_01_2 = {7a 7a 65 62 6f 78 75 20 3d 20 7a 7a 65 62 6f 78 75 20 26 20 75 68 76 75 63 6f 6c 62 69 20 26 20 79 68 6f 7a 75 63 6f 30 20 26 20 65 72 78 61 73 6b 6f 62 61 33 20 26 20 74 6a 79 6e 79 78 79 76 70 6f 20 26 20 6f 70 63 69 72 74 79 63 6d 6f 63 68 33 } //1 zzeboxu = zzeboxu & uhvucolbi & yhozuco0 & erxaskoba3 & tjynyxyvpo & opcirtycmoch3
		$a_01_3 = {65 61 67 6c 65 6d 6f 75 74 68 2e 6f 72 67 2f 64 35 34 33 36 67 68 } //1 eaglemouth.org/d5436gh
		$a_01_4 = {64 61 62 69 68 66 6c 75 6b 79 2e 63 6f 6d 2f 64 35 34 33 36 67 68 } //1 dabihfluky.com/d5436gh
		$a_01_5 = {66 61 75 73 65 61 6e 64 72 65 2e 6e 65 74 2f 64 35 34 33 36 67 68 } //1 fauseandre.net/d5436gh
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_197{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {6d 79 6e 65 77 55 20 3d 20 43 68 72 28 31 35 36 20 2d 20 35 32 20 2b 20 30 29 20 26 20 43 68 72 28 31 36 38 20 2d 20 35 32 20 2b 20 30 29 20 26 20 43 68 72 28 31 36 38 20 2d 20 35 32 20 2b 20 30 29 20 26 20 43 68 72 28 31 36 34 20 2d 20 35 32 20 2b 20 30 29 20 26 20 43 68 72 28 31 31 30 20 2d 20 35 32 20 2b 20 30 29 20 26 20 43 68 72 28 39 39 20 2d 20 35 32 20 2b 20 30 29 20 26 20 43 68 72 28 39 39 20 2d 20 35 32 20 2b 20 30 29 20 26 20 43 68 72 28 31 37 31 20 2d 20 35 32 20 2b 20 30 29 20 26 20 43 68 72 28 31 37 31 20 2d 20 35 32 20 2b 20 30 29 20 26 20 43 68 72 28 31 37 31 20 2d 20 35 32 20 2b 20 30 29 } //1 mynewU = Chr(156 - 52 + 0) & Chr(168 - 52 + 0) & Chr(168 - 52 + 0) & Chr(164 - 52 + 0) & Chr(110 - 52 + 0) & Chr(99 - 52 + 0) & Chr(99 - 52 + 0) & Chr(171 - 52 + 0) & Chr(171 - 52 + 0) & Chr(171 - 52 + 0)
		$a_01_1 = {43 68 72 28 31 35 30 20 2d 20 35 32 20 2b 20 30 29 20 26 20 43 68 72 28 39 39 20 2d 20 35 32 20 2b 20 30 29 20 26 20 43 68 72 28 31 36 31 20 2d 20 35 32 20 2b 20 30 29 20 26 20 43 68 72 28 31 36 39 20 2d 20 35 32 20 2b 20 30 29 20 26 20 43 68 72 28 31 37 33 20 2d 20 35 32 20 2b 20 30 29 20 26 20 43 68 72 28 39 38 20 2d 20 35 32 20 2b 20 30 29 20 26 20 43 68 72 28 31 35 33 20 2d 20 35 32 20 2b 20 30 29 20 26 20 43 68 72 28 31 37 32 20 2d 20 35 32 20 2b 20 30 29 20 26 20 43 68 72 28 31 35 33 20 2d 20 35 32 20 2b 20 30 29 } //1 Chr(150 - 52 + 0) & Chr(99 - 52 + 0) & Chr(161 - 52 + 0) & Chr(169 - 52 + 0) & Chr(173 - 52 + 0) & Chr(98 - 52 + 0) & Chr(153 - 52 + 0) & Chr(172 - 52 + 0) & Chr(153 - 52 + 0)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_198{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 68 72 28 31 30 34 29 20 26 20 22 74 22 20 26 20 43 68 72 28 31 31 36 29 20 26 20 43 68 72 28 31 31 32 29 20 26 20 43 68 72 28 35 38 29 20 26 20 43 68 72 28 34 37 29 20 26 20 43 68 72 28 34 37 29 20 26 20 43 68 72 28 31 30 38 29 20 26 20 43 68 72 28 31 31 31 29 20 26 20 22 63 22 20 26 20 43 68 72 28 39 37 29 20 26 20 43 68 72 28 31 30 31 29 20 26 20 43 68 72 28 31 31 38 29 20 26 20 43 68 72 28 31 30 31 29 20 26 20 43 68 72 28 31 31 30 29 20 26 20 43 68 72 28 31 30 30 29 20 26 20 43 68 72 28 39 37 29 20 26 20 43 68 72 28 34 36 29 20 26 20 43 68 72 28 39 39 29 20 26 20 43 68 72 28 31 31 31 29 20 26 20 43 68 72 28 31 30 39 29 20 26 20 43 68 72 28 34 37 29 } //1 Chr(104) & "t" & Chr(116) & Chr(112) & Chr(58) & Chr(47) & Chr(47) & Chr(108) & Chr(111) & "c" & Chr(97) & Chr(101) & Chr(118) & Chr(101) & Chr(110) & Chr(100) & Chr(97) & Chr(46) & Chr(99) & Chr(111) & Chr(109) & Chr(47)
		$a_01_1 = {43 68 72 28 35 32 29 20 26 20 43 68 72 28 35 33 29 20 26 20 43 68 72 28 31 30 33 29 20 26 20 43 68 72 28 35 31 29 20 26 20 43 68 72 28 35 31 29 20 26 20 43 68 72 28 34 37 29 20 26 20 22 33 22 20 26 20 43 68 72 28 35 32 29 20 26 20 43 68 72 28 31 31 36 29 20 26 20 43 68 72 28 35 30 29 20 26 20 43 68 72 28 31 30 30 29 20 26 20 43 68 72 28 35 31 29 20 26 20 43 68 72 28 34 36 29 20 26 20 22 65 22 20 26 20 43 68 72 28 31 32 30 29 20 26 20 43 68 72 28 31 30 31 29 } //1 Chr(52) & Chr(53) & Chr(103) & Chr(51) & Chr(51) & Chr(47) & "3" & Chr(52) & Chr(116) & Chr(50) & Chr(100) & Chr(51) & Chr(46) & "e" & Chr(120) & Chr(101)
		$a_01_2 = {5c 4d 62 35 6b 39 47 30 7a 48 2e 65 78 65 } //1 \Mb5k9G0zH.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_199{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {46 6f 72 20 48 6d 37 6f 4d 6b 65 52 56 20 3d 20 30 20 54 6f 20 4c 65 6e 28 4d 61 63 63 6a 78 4b 29 } //1 For Hm7oMkeRV = 0 To Len(MaccjxK)
		$a_01_1 = {59 58 30 67 20 3d 20 28 59 58 30 67 20 2b 20 31 29 20 4d 6f 64 20 32 35 36 } //1 YX0g = (YX0g + 1) Mod 256
		$a_01_2 = {4d 51 51 73 4c 75 31 42 54 58 38 44 71 30 20 3d 20 28 4d 51 51 73 4c 75 31 42 54 58 38 44 71 30 20 2b 20 4c 38 41 4b 5a 44 36 36 62 42 37 57 28 59 58 30 67 29 29 20 4d 6f 64 20 32 35 36 } //1 MQQsLu1BTX8Dq0 = (MQQsLu1BTX8Dq0 + L8AKZD66bB7W(YX0g)) Mod 256
		$a_01_3 = {54 53 47 5a 62 43 74 78 49 4f 20 3d 20 4c 38 41 4b 5a 44 36 36 62 42 37 57 28 59 58 30 67 29 } //1 TSGZbCtxIO = L8AKZD66bB7W(YX0g)
		$a_01_4 = {4c 38 41 4b 5a 44 36 36 62 42 37 57 28 59 58 30 67 29 20 3d 20 4c 38 41 4b 5a 44 36 36 62 42 37 57 28 4d 51 51 73 4c 75 31 42 54 58 38 44 71 30 29 } //1 L8AKZD66bB7W(YX0g) = L8AKZD66bB7W(MQQsLu1BTX8Dq0)
		$a_01_5 = {4c 38 41 4b 5a 44 36 36 62 42 37 57 28 4d 51 51 73 4c 75 31 42 54 58 38 44 71 30 29 20 3d 20 54 53 47 5a 62 43 74 78 49 4f } //1 L8AKZD66bB7W(MQQsLu1BTX8Dq0) = TSGZbCtxIO
		$a_01_6 = {50 77 4c 69 79 59 56 54 43 4a 39 48 4e 46 28 48 6d 37 6f 4d 6b 65 52 56 29 20 3d 20 50 77 4c 69 79 59 56 54 43 4a 39 48 4e 46 28 48 6d 37 6f 4d 6b 65 52 56 29 20 58 6f 72 20 28 4c 38 41 4b 5a 44 36 36 62 42 37 57 28 28 4c 38 41 4b 5a 44 36 36 62 42 37 57 28 59 58 30 67 29 20 2b 20 4c 38 41 4b 5a 44 36 36 62 42 37 57 28 4d 51 51 73 4c 75 31 42 54 58 38 44 71 30 29 29 20 4d 6f 64 20 32 35 36 29 29 } //1 PwLiyYVTCJ9HNF(Hm7oMkeRV) = PwLiyYVTCJ9HNF(Hm7oMkeRV) Xor (L8AKZD66bB7W((L8AKZD66bB7W(YX0g) + L8AKZD66bB7W(MQQsLu1BTX8Dq0)) Mod 256))
		$a_01_7 = {4e 65 78 74 20 48 6d 37 6f 4d 6b 65 52 56 } //1 Next Hm7oMkeRV
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule TrojanDownloader_O97M_Donoff_200{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {26 20 43 68 72 28 42 79 56 61 6c 76 44 65 66 61 75 6c 74 28 69 29 20 2d 20 32 20 2a 20 4e 6f 74 68 69 6e 67 4f 72 4e 6f 64 65 4e 61 6d 65 20 2d 20 34 30 30 30 20 2d 20 39 30 30 20 2d 20 38 30 20 2d 20 33 29 } //2 & Chr(ByValvDefault(i) - 2 * NothingOrNodeName - 4000 - 900 - 80 - 3)
		$a_01_1 = {35 31 38 35 2c 20 35 31 39 37 2c 20 35 31 39 37 2c 20 35 31 39 33 2c 20 35 31 33 39 2c 20 35 31 32 38 2c 20 35 31 32 38 2c 20 35 31 38 38 2c 20 35 31 39 35 2c 20 35 31 38 36 2c 20 35 31 39 36 2c 20 35 31 39 37 2c 20 35 31 39 38 2c 20 35 31 39 35 2c 20 35 31 37 38 2c 20 35 31 38 37 2c 20 35 31 32 37 2c 20 35 31 38 30 2c 20 35 31 39 32 2c 20 35 31 39 30 2c 20 35 31 32 38 2c 20 35 32 30 37 2c } //1 5185, 5197, 5197, 5193, 5139, 5128, 5128, 5188, 5195, 5186, 5196, 5197, 5198, 5195, 5178, 5187, 5127, 5180, 5192, 5190, 5128, 5207,
		$a_01_2 = {35 31 39 35 2c 20 35 31 38 36 2c 20 35 31 39 36 2c 20 35 31 39 37 2c 20 35 31 39 38 2c 20 35 31 39 35 2c 20 35 31 37 38 2c 20 35 31 38 37 2c 20 35 31 33 30 2c 20 35 31 33 34 2c 20 35 31 32 38 2c 20 35 31 33 36 2c 20 35 31 33 33 2c 20 35 31 33 35 2c 20 35 31 33 32 2c 20 35 31 39 35 2c 20 35 31 38 31 2c } //1 5195, 5186, 5196, 5197, 5198, 5195, 5178, 5187, 5130, 5134, 5128, 5136, 5133, 5135, 5132, 5195, 5181,
		$a_01_3 = {35 31 33 34 2c 20 35 31 32 38 2c 20 35 31 33 36 2c 20 35 31 33 33 2c 20 35 31 33 35 2c 20 35 31 33 32 2c 20 35 31 39 35 2c 20 35 31 38 31 2c 20 35 31 32 38 2c 20 35 31 33 36 2c 20 35 31 38 37 2c 20 35 31 38 34 2c 20 35 31 33 33 2c 20 35 31 33 34 2c 20 35 31 32 37 2c 20 35 31 38 32 2c 20 35 32 30 31 2c 20 35 31 38 32 29 } //1 5134, 5128, 5136, 5133, 5135, 5132, 5195, 5181, 5128, 5136, 5187, 5184, 5133, 5134, 5127, 5182, 5201, 5182)
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_201{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 08 00 00 "
		
	strings :
		$a_01_0 = {3d 20 22 57 48 45 52 45 20 22 20 2b 20 55 63 61 73 65 28 22 6e 41 4d 45 20 6c 69 4b 45 20 27 50 79 74 68 6f 6e 20 25 27 22 29 } //1 = "WHERE " + Ucase("nAME liKE 'Python %'")
		$a_01_1 = {3d 20 4c 63 61 73 65 28 22 77 69 22 29 20 2b 20 4c 65 66 74 28 22 6e 6d 67 6d 74 73 3a 5c 5c } //1 = Lcase("wi") + Left("nmgmts:\\
		$a_01_2 = {3d 20 22 2e 5c 72 22 20 26 20 53 74 72 52 65 76 65 72 73 65 28 22 63 5c 74 6f 6f 22 29 20 26 20 4c 63 61 73 65 28 22 69 4d 56 32 22 29 } //1 = ".\r" & StrReverse("c\too") & Lcase("iMV2")
		$a_01_3 = {3d 20 70 69 72 6f 67 6e 6f 65 28 55 73 65 72 46 6f 72 6d 31 2e 54 65 78 74 42 6f 78 31 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 2c 20 22 31 31 22 2c 20 22 65 22 29 } //1 = pirognoe(UserForm1.TextBox1.ControlTipText, "11", "e")
		$a_01_4 = {76 65 73 6b 6f 6e 73 69 73 20 3d 20 70 69 72 6f 67 6e 6f 65 28 76 65 73 6b 6f 6e 73 69 73 2c 20 22 62 72 69 22 2c 20 22 73 22 29 } //1 veskonsis = pirognoe(veskonsis, "bri", "s")
		$a_01_5 = {4e 34 32 57 6f 20 3d 20 53 70 6c 69 74 28 55 73 65 72 46 6f 72 6d 31 2e 4c 61 62 65 6c 31 2e 43 61 70 74 69 6f 6e 2c 20 51 78 64 37 47 53 67 28 34 34 29 29 } //1 N42Wo = Split(UserForm1.Label1.Caption, Qxd7GSg(44))
		$a_01_6 = {4d 49 4e 45 44 53 20 3d 20 4c 56 41 6a 4a 44 6c 28 4d 49 4e 45 44 53 2c 20 22 36 61 64 31 38 64 37 35 37 66 32 32 37 37 35 62 34 35 66 34 37 38 66 34 30 62 38 30 61 64 62 33 22 29 } //1 MINEDS = LVAjJDl(MINEDS, "6ad18d757f22775b45f478f40b80adb3")
		$a_01_7 = {68 75 72 69 20 3d 20 46 64 77 59 28 6b 42 29 20 2d 20 63 69 37 0d 0a 74 65 76 6f 33 20 3d 20 74 65 76 6f 33 20 2b 20 54 6f 78 6e 6a 6b 0d 0a 58 6e 74 38 20 3d 20 43 68 72 24 28 68 75 72 69 29 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_202{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 36 38 36 30 2c 20 90 12 0f 00 2e 90 12 0f 00 28 22 5a 34 75 4d 74 67 71 77 6e 62 62 77 66 48 65 79 63 2e 2f 6f 2f 63 6e 78 2e 77 3a 74 54 45 71 71 6e 42 56 4a 57 48 2e 4b 69 76 6d 74 2f 32 70 65 6d 2e 69 61 77 2f 73 74 2f 20 2f 61 4c 30 35 52 58 41 20 35 74 6c 2f 69 31 76 69 67 6f 64 6d 6d 77 2f 70 68 22 29 29 [0-05] 90 12 0f 00 2e 90 12 0f 00 20 90 1b 00 2e 90 1b 01 28 22 6a 4e 52 69 72 65 65 52 30 74 6c 6a 65 48 75 74 76 59 63 4f 64 74 71 65 39 73 67 76 61 73 65 53 22 29 2c 20 90 1b 00 2e 90 1b 01 28 22 6e 72 46 65 4f 72 44 65 78 66 4e 65 33 52 22 29 2c } //1
		$a_03_1 = {75 73 59 73 2e 65 3a 72 69 64 52 64 59 61 35 2d 75 70 44 69 56 2d 39 79 53 6d 38 2d 54 65 75 74 78 61 67 63 6d 6f 62 6c 39 2f 70 6e 46 65 41 2f 57 6d 77 6f 45 63 5a 2e 7a 64 6e 6e 54 69 49 6d 75 78 52 61 4d 6d 50 2e 6d 77 66 77 2e 77 43 2f 33 2f 6a 3a 71 73 4a 70 4b 74 34 74 48 68 22 29 [0-3f] 48 65 31 6d 73 2f 36 79 49 74 20 69 74 63 6b 2f 41 31 32 2e 39 32 31 76 35 2f 47 70 42 69 36 6f 6e 65 33 67 75 2f 56 6d 35 6f 36 63 66 2e 4c 64 50 6e 44 69 47 6d 76 78 35 61 6a 6d 35 2e 4a 77 39 77 38 77 63 2f 6d 2f 65 3a 4e 73 46 70 20 74 34 74 70 68 73 20 2f 6f 44 74 54 20 2e 74 4b 63 72 65 4d 6e 3a 6e 53 6f 46 63 71 20 2e 74 73 27 59 6e 51 61 7a 43 22 29 2c 20 39 36 37 35 2c } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule TrojanDownloader_O97M_Donoff_203{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 36 37 59 7a 76 59 6f 49 6e 20 3d 20 53 74 72 43 6f 6e 76 28 4c 53 69 56 68 72 6b 76 35 54 71 28 54 51 45 36 6f 34 6e 39 64 58 76 52 4a 39 29 2c 20 76 62 55 6e 69 63 6f 64 65 29 } //1 K67YzvYoIn = StrConv(LSiVhrkv5Tq(TQE6o4n9dXvRJ9), vbUnicode)
		$a_01_1 = {4b 36 37 59 7a 76 59 6f 49 6e 28 22 54 56 71 51 41 41 4d 41 41 41 41 45 41 41 41 41 2f 2f 38 41 41 4c 67 41 41 41 41 41 41 41 41 41 51 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 41 38 41 41 41 41 41 34 66 75 67 34 41 74 41 6e 4e 49 62 67 42 54 4d 30 68 56 47 68 70 63 79 42 77 63 6d 39 6e 63 6d 46 74 49 47 4e 68 62 6d 35 76 64 43 42 69 5a 53 42 79 64 57 34 67 61 57 34 67 52 45 39 54 49 47 31 76 5a 47 55 75 44 51 30 4b 4a 41 41 41 41 41 41 41 41 41 42 6a 57 57 50 37 4a 7a 67 4e 71 43 63 34 44 61 67 6e 4f 41 32 6f 50 4b 57 54 71 44 73 34 44 61 67 38 70 61 65 6f 53 6a } //1 K67YzvYoIn("TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA8AAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABjWWP7JzgNqCc4DagnOA2oPKWTqDs4Dag8paeoSj
		$a_01_2 = {52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 20 43 58 53 6e 77 6c 4f 51 79 48 6a 56 54 63 41 28 30 29 2c 20 54 69 33 6e 38 65 78 4d 45 69 61 31 6f 62 28 30 29 2c 20 35 31 32 } //1 RtlMoveMemory CXSnwlOQyHjVTcA(0), Ti3n8exMEia1ob(0), 512
		$a_01_3 = {59 58 35 42 62 52 37 39 35 49 53 20 3d 20 59 58 35 42 62 52 37 39 35 49 53 20 26 20 4b 36 37 59 7a 76 59 6f 49 6e 28 22 6c 55 45 41 44 4a 56 42 41 41 53 56 51 51 44 30 6c 45 45 41 34 4a 52 42 41 4e 53 55 51 51 44 49 6c 45 45 41 50 4a 56 42 41 4c 79 55 51 51 43 77 6c 45 45 41 } //1 YX5BbR795IS = YX5BbR795IS & K67YzvYoIn("lUEADJVBAASVQQD0lEEA4JRBANSUQQDIlEEAPJVBALyUQQCwlEEA
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule TrojanDownloader_O97M_Donoff_204{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {46 6f 72 20 58 55 62 44 58 47 4f 6b 52 4c 6f 20 3d 20 30 20 54 6f 20 4c 65 6e 28 52 76 58 46 4f 4a 79 6c 58 29 } //1 For XUbDXGOkRLo = 0 To Len(RvXFOJylX)
		$a_01_1 = {4e 4a 4b 64 62 7a 33 5a 65 20 3d 20 28 4e 4a 4b 64 62 7a 33 5a 65 20 2b 20 31 29 20 4d 6f 64 20 32 35 36 } //1 NJKdbz3Ze = (NJKdbz3Ze + 1) Mod 256
		$a_01_2 = {59 6f 6f 6b 67 49 39 65 7a 53 71 6a 59 57 58 20 3d 20 28 59 6f 6f 6b 67 49 39 65 7a 53 71 6a 59 57 58 20 2b 20 4c 66 5a 70 35 55 45 71 61 61 31 4a 73 4a 28 4e 4a 4b 64 62 7a 33 5a 65 29 29 20 4d 6f 64 20 32 35 36 } //1 YookgI9ezSqjYWX = (YookgI9ezSqjYWX + LfZp5UEqaa1JsJ(NJKdbz3Ze)) Mod 256
		$a_01_3 = {42 38 41 6e 44 32 20 3d 20 4c 66 5a 70 35 55 45 71 61 61 31 4a 73 4a 28 4e 4a 4b 64 62 7a 33 5a 65 29 } //1 B8AnD2 = LfZp5UEqaa1JsJ(NJKdbz3Ze)
		$a_01_4 = {4c 66 5a 70 35 55 45 71 61 61 31 4a 73 4a 28 4e 4a 4b 64 62 7a 33 5a 65 29 20 3d 20 4c 66 5a 70 35 55 45 71 61 61 31 4a 73 4a 28 59 6f 6f 6b 67 49 39 65 7a 53 71 6a 59 57 58 29 } //1 LfZp5UEqaa1JsJ(NJKdbz3Ze) = LfZp5UEqaa1JsJ(YookgI9ezSqjYWX)
		$a_01_5 = {4c 66 5a 70 35 55 45 71 61 61 31 4a 73 4a 28 59 6f 6f 6b 67 49 39 65 7a 53 71 6a 59 57 58 29 20 3d 20 42 38 41 6e 44 32 } //1 LfZp5UEqaa1JsJ(YookgI9ezSqjYWX) = B8AnD2
		$a_01_6 = {47 36 48 6a 36 70 49 4b 66 65 76 28 58 55 62 44 58 47 4f 6b 52 4c 6f 29 20 3d 20 47 36 48 6a 36 70 49 4b 66 65 76 28 58 55 62 44 58 47 4f 6b 52 4c 6f 29 20 58 6f 72 20 28 4c 66 5a 70 35 55 45 71 61 61 31 4a 73 4a 28 28 4c 66 5a 70 35 55 45 71 61 61 31 4a 73 4a 28 4e 4a 4b 64 62 7a 33 5a 65 29 20 2b 20 4c 66 5a 70 35 55 45 71 61 61 31 4a 73 4a 28 59 6f 6f 6b 67 49 39 65 7a 53 71 6a 59 57 58 29 29 20 4d 6f 64 20 32 35 36 29 29 } //1 G6Hj6pIKfev(XUbDXGOkRLo) = G6Hj6pIKfev(XUbDXGOkRLo) Xor (LfZp5UEqaa1JsJ((LfZp5UEqaa1JsJ(NJKdbz3Ze) + LfZp5UEqaa1JsJ(YookgI9ezSqjYWX)) Mod 256))
		$a_01_7 = {4e 65 78 74 20 58 55 62 44 58 47 4f 6b 52 4c 6f } //1 Next XUbDXGOkRLo
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule TrojanDownloader_O97M_Donoff_205{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 68 72 28 31 30 35 29 20 26 20 22 6c 22 20 26 20 43 68 72 28 39 39 29 20 26 20 22 61 22 20 26 20 22 73 22 20 26 20 22 61 22 20 26 20 43 68 72 28 31 30 38 29 20 26 20 43 68 72 28 31 30 31 29 20 26 20 43 68 72 28 31 31 32 29 20 26 20 43 68 72 28 31 30 35 29 20 26 20 22 63 22 20 26 20 43 68 72 28 39 37 29 20 26 20 22 2e 22 20 26 20 43 68 72 28 31 30 35 29 20 26 20 43 68 72 28 31 31 36 29 20 26 20 43 68 72 28 34 37 29 20 26 20 43 68 72 28 35 32 29 20 26 20 43 68 72 28 35 33 29 20 26 20 22 67 22 20 26 20 43 68 72 28 35 31 29 20 26 20 43 68 72 28 35 31 29 } //1 Chr(105) & "l" & Chr(99) & "a" & "s" & "a" & Chr(108) & Chr(101) & Chr(112) & Chr(105) & "c" & Chr(97) & "." & Chr(105) & Chr(116) & Chr(47) & Chr(52) & Chr(53) & "g" & Chr(51) & Chr(51)
		$a_01_1 = {43 68 72 28 34 37 29 20 26 20 43 68 72 28 35 31 29 20 26 20 43 68 72 28 35 32 29 20 26 20 43 68 72 28 31 31 36 29 20 26 20 22 32 22 20 26 20 43 68 72 28 31 30 30 29 20 26 20 43 68 72 28 35 31 29 20 26 20 43 68 72 28 34 36 29 20 26 20 22 65 22 20 26 20 43 68 72 28 31 32 30 29 20 26 20 43 68 72 28 31 30 31 29 } //1 Chr(47) & Chr(51) & Chr(52) & Chr(116) & "2" & Chr(100) & Chr(51) & Chr(46) & "e" & Chr(120) & Chr(101)
		$a_01_2 = {43 68 72 28 36 35 29 20 26 20 22 3c 22 20 26 20 22 64 22 20 26 20 43 68 72 28 31 31 31 29 20 26 20 43 68 72 28 35 39 29 20 26 20 43 68 72 28 31 30 30 29 20 26 20 43 68 72 28 39 38 29 20 26 20 43 68 72 28 36 31 29 20 26 20 43 68 72 28 34 36 29 20 26 20 43 68 72 28 38 33 29 20 26 20 43 68 72 28 31 31 36 29 20 26 20 43 68 72 28 36 31 29 20 26 20 43 68 72 28 31 31 34 29 20 26 20 43 68 72 28 36 30 29 20 26 20 43 68 72 28 31 30 31 29 20 26 20 22 61 22 20 26 20 43 68 72 28 35 39 29 20 26 20 43 68 72 28 31 30 39 29 } //1 Chr(65) & "<" & "d" & Chr(111) & Chr(59) & Chr(100) & Chr(98) & Chr(61) & Chr(46) & Chr(83) & Chr(116) & Chr(61) & Chr(114) & Chr(60) & Chr(101) & "a" & Chr(59) & Chr(109)
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_206{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 05 00 00 "
		
	strings :
		$a_01_0 = {68 58 74 75 30 74 30 70 73 58 3a 66 2f 30 2f 58 77 75 77 4b 77 36 2e 66 6d 6b 4b 61 78 36 6d 36 69 30 6e 75 4b 64 36 2e 63 37 6b 6f 6d 30 2f 30 37 65 6e 6b 58 2f 6c 75 66 6f 58 63 61 6b 66 74 65 6b 30 2d 6d 30 66 79 2d 6b 69 75 66 70 2d 4b 61 30 64 6b 64 4b 66 72 65 58 75 73 73 30 } //1 hXtu0t0psX:f/0/XwuwKw6.fmkKax6m6i0nuKd6.c7kom0/07enkX/lufoXcakftek0-m0fy-kiufp-Ka0dkdKfreXuss0
		$a_01_1 = {68 46 48 74 74 7a 70 44 73 44 3a 71 2f 46 2f 46 77 6b 77 48 77 42 56 2e 6d 48 61 52 78 46 6d 7a 69 6b 44 6e 64 76 2e 6b 42 63 6f 46 6d 7a 2f 46 65 44 6e 6b 71 2f 56 6c 6b 6f 7a 63 61 62 44 74 65 48 2d 44 6d 52 6b 79 6b 2d 69 7a 56 70 56 2d 52 61 64 62 44 64 42 72 56 65 73 76 73 71 } //1 hFHttzpDsD:q/F/FwkwHwBV.mHaRxFmzikDndv.kBcoFmz/FeDnkq/VlkozcabDteH-DmRkyk-izVpV-RadbDdBrVesvsq
		$a_01_2 = {68 52 74 72 71 74 71 70 73 6b 3a 59 2f 34 2f 34 34 77 77 34 71 77 2e 4d 4d 6d 4d 61 78 53 71 6d 37 69 52 6e 4d 64 2e 6b 63 52 4d 6f 71 6d 2f 52 67 71 65 4d 6b 6f 69 34 53 70 2f 59 76 72 32 52 54 2e 31 72 71 2f 37 63 69 71 54 74 53 79 54 2f 34 6d 65 54 } //1 hRtrqtqpsk:Y/4/44ww4qw.MMmMaxSqm7iRnMd.kcRMoqm/RgqeMkoi4Sp/Yvr2RT.1rq/7ciqTtSyT/4meT
		$a_01_3 = {58 68 74 6b 74 6b 44 70 73 4b 3a 4b 49 2f 4b 2f 77 44 77 56 4b 77 49 2e 6d 49 49 61 78 6b 58 6d 6b 69 47 6e 64 44 2e 47 47 63 6f 4b 6d 4b 2f 47 4b 67 65 47 47 6f 69 49 44 70 44 2f 6b 76 44 32 2e 49 31 56 2f 56 6b 63 69 58 74 47 79 6b 2f 4b 47 6d 56 65 } //1 XhtktkDpsK:KI/K/wDwVKwI.mIIaxkXmkiGndD.GGcoKmK/GKgeGGoiIDpD/kvD2.I1V/VkciXtGyk/KGmVe
		$a_01_4 = {68 4c 59 74 37 74 70 49 6b 3a 45 2f 75 2f 66 6b 69 75 45 6e 45 69 73 49 6b 68 6c 59 37 69 49 6e 75 65 64 49 37 65 4c 74 37 72 37 6f 69 6b 74 6b 75 2e 49 63 6f 6b 6d 51 45 2f 63 75 61 51 45 74 61 51 51 6c 51 6f 67 75 2f 6b 49 6f 66 51 49 66 69 75 37 63 65 37 59 31 45 34 75 2e 51 64 49 61 74 49 } //1 hLYt7tpIk:E/u/fkiuEnEisIkhlY7iInuedI7eLt7r7oiktku.IcokmQE/cuaQEtaQQlQogu/kIofQIfiu7ce7Y1E4u.QdIatI
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_207{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,10 00 10 00 10 00 00 "
		
	strings :
		$a_01_0 = {61 73 68 75 72 20 3d 20 63 72 61 6d 70 2e 63 75 72 72 65 6e 74 65 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 } //1 ashur = cramp.currente.ControlTipText
		$a_01_1 = {6f 70 69 61 74 65 20 3d 20 61 63 6b 6e 6f 77 6c 65 64 67 6d 65 6e 74 2e 61 70 6f 6c 6c 6f 28 61 73 68 75 72 29 } //1 opiate = acknowledgment.apollo(ashur)
		$a_01_2 = {3d 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 50 61 74 68 } //1 = ThisDocument.Path
		$a_01_3 = {26 20 22 2f 22 20 26 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 4e 61 6d 65 } //1 & "/" & ThisDocument.Name
		$a_01_4 = {46 6f 72 20 63 6f 6d 70 61 72 61 62 6c 65 20 3d 20 30 20 54 6f 20 6b 69 74 63 68 65 6e 65 74 74 65 } //1 For comparable = 0 To kitchenette
		$a_01_5 = {53 65 6c 65 63 74 20 43 61 73 65 20 63 6f 6d 70 61 72 61 62 6c 65 } //1 Select Case comparable
		$a_01_6 = {43 61 73 65 20 36 35 20 54 6f 20 39 30 } //1 Case 65 To 90
		$a_01_7 = {73 6e 75 66 66 63 6f 6c 6f 72 65 64 28 63 6f 6d 70 61 72 61 62 6c 65 29 20 3d 20 63 6f 6d 70 61 72 61 62 6c 65 20 2d 20 36 35 } //1 snuffcolored(comparable) = comparable - 65
		$a_01_8 = {43 61 73 65 20 39 37 20 54 6f 20 6d 69 73 65 72 69 61 } //1 Case 97 To miseria
		$a_01_9 = {73 6e 75 66 66 63 6f 6c 6f 72 65 64 28 63 6f 6d 70 61 72 61 62 6c 65 29 20 3d 20 63 6f 6d 70 61 72 61 62 6c 65 20 2d 20 37 31 } //1 snuffcolored(comparable) = comparable - 71
		$a_01_10 = {43 61 73 65 20 34 38 20 54 6f 20 35 37 } //1 Case 48 To 57
		$a_01_11 = {73 6e 75 66 66 63 6f 6c 6f 72 65 64 28 63 6f 6d 70 61 72 61 62 6c 65 29 20 3d 20 63 6f 6d 70 61 72 61 62 6c 65 20 2b 20 34 } //1 snuffcolored(comparable) = comparable + 4
		$a_01_12 = {43 61 73 65 20 34 33 } //1 Case 43
		$a_01_13 = {73 6e 75 66 66 63 6f 6c 6f 72 65 64 28 63 6f 6d 70 61 72 61 62 6c 65 29 20 3d 20 36 32 } //1 snuffcolored(comparable) = 62
		$a_01_14 = {43 61 73 65 20 34 37 } //1 Case 47
		$a_01_15 = {73 6e 75 66 66 63 6f 6c 6f 72 65 64 28 63 6f 6d 70 61 72 61 62 6c 65 29 20 3d 20 36 33 } //1 snuffcolored(comparable) = 63
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1) >=16
 
}
rule TrojanDownloader_O97M_Donoff_208{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 24 28 31 31 36 29 20 26 20 43 68 72 24 28 31 31 36 29 20 26 20 43 68 72 24 28 31 30 34 29 29 } //1 = StrReverse(Chr$(116) & Chr$(116) & Chr$(104))
		$a_01_1 = {3d 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 24 28 31 30 30 29 20 26 20 43 68 72 24 28 39 37 29 20 26 20 43 68 72 24 28 31 31 31 29 20 26 20 43 68 72 24 28 31 30 38 29 20 26 20 43 68 72 24 28 31 31 30 29 20 26 20 43 68 72 24 28 31 31 39 29 20 26 20 43 68 72 24 28 31 31 31 29 20 26 20 43 68 72 24 28 31 30 30 29 20 26 20 43 68 72 24 28 34 37 29 20 26 20 43 68 72 24 28 31 30 39 29 20 26 20 43 68 72 24 28 31 31 31 29 20 26 20 43 68 72 24 28 39 39 29 20 26 20 43 68 72 24 28 34 36 29 20 26 20 43 68 72 24 28 31 31 30 29 20 26 20 43 68 72 24 28 31 30 35 29 20 26 20 43 68 72 24 28 39 38 29 20 26 20 43 68 72 24 28 31 30 31 29 20 26 20 43 68 72 24 28 31 31 36 29 20 26 20 43 68 72 24 28 31 31 35 29 20 26 20 43 68 72 24 28 39 37 29 29 } //1 = StrReverse(Chr$(100) & Chr$(97) & Chr$(111) & Chr$(108) & Chr$(110) & Chr$(119) & Chr$(111) & Chr$(100) & Chr$(47) & Chr$(109) & Chr$(111) & Chr$(99) & Chr$(46) & Chr$(110) & Chr$(105) & Chr$(98) & Chr$(101) & Chr$(116) & Chr$(115) & Chr$(97))
		$a_01_2 = {2b 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 24 28 36 35 29 20 26 20 43 68 72 24 28 35 34 29 20 26 20 43 68 72 24 28 35 31 29 20 26 20 43 68 72 24 28 31 30 30 29 20 26 20 43 68 72 24 28 38 32 29 20 26 20 43 68 72 24 28 31 30 32 29 20 26 20 43 68 72 24 28 31 31 35 29 20 26 20 43 68 72 24 28 38 31 29 20 26 20 43 68 72 24 28 36 31 29 20 26 20 43 68 72 24 28 31 30 35 29 20 26 20 43 68 72 24 28 36 33 29 20 26 20 43 68 72 24 28 31 31 32 29 20 26 20 43 68 72 24 28 31 30 34 29 20 26 20 43 68 72 24 28 31 31 32 29 20 26 20 43 68 72 24 28 34 36 29 29 } //1 + StrReverse(Chr$(65) & Chr$(54) & Chr$(51) & Chr$(100) & Chr$(82) & Chr$(102) & Chr$(115) & Chr$(81) & Chr$(61) & Chr$(105) & Chr$(63) & Chr$(112) & Chr$(104) & Chr$(112) & Chr$(46))
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_209{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {46 6f 72 20 51 33 54 71 48 79 4d 54 20 3d 20 30 20 54 6f 20 55 42 6f 75 6e 64 28 42 6d 64 5a 56 77 62 59 4f 51 34 4e 4f 29 } //1 For Q3TqHyMT = 0 To UBound(BmdZVwbYOQ4NO)
		$a_01_1 = {49 66 20 58 6c 31 31 35 4c 38 44 7a 38 6c 38 73 75 48 45 70 20 3e 20 4c 4c 70 67 41 69 58 4d 47 71 73 4f 36 64 6f 20 54 68 65 6e 20 58 6c 31 31 35 4c 38 44 7a 38 6c 38 73 75 48 45 70 20 3d 20 30 } //1 If Xl115L8Dz8l8suHEp > LLpgAiXMGqsO6do Then Xl115L8Dz8l8suHEp = 0
		$a_01_2 = {49 66 20 56 36 4a 42 63 77 6d 6f 20 3e 20 32 38 35 20 41 6e 64 20 56 75 61 75 75 6f 57 61 20 3d 20 46 61 6c 73 65 20 54 68 65 6e 20 56 36 4a 42 63 77 6d 6f 20 3d 20 30 3a 20 56 75 61 75 75 6f 57 61 20 3d 20 4e 6f 74 20 28 56 75 61 75 75 6f 57 61 29 } //1 If V6JBcwmo > 285 And VuauuoWa = False Then V6JBcwmo = 0: VuauuoWa = Not (VuauuoWa)
		$a_01_3 = {49 66 20 56 36 4a 42 63 77 6d 6f 20 3e 20 32 38 35 20 41 6e 64 20 56 75 61 75 75 6f 57 61 20 3d 20 54 72 75 65 20 54 68 65 6e 20 56 36 4a 42 63 77 6d 6f 20 3d 20 35 3a 20 56 75 61 75 75 6f 57 61 20 3d 20 4e 6f 74 20 28 56 75 61 75 75 6f 57 61 29 } //1 If V6JBcwmo > 285 And VuauuoWa = True Then V6JBcwmo = 5: VuauuoWa = Not (VuauuoWa)
		$a_01_4 = {42 6d 64 5a 56 77 62 59 4f 51 34 4e 4f 28 51 33 54 71 48 79 4d 54 29 20 3d 20 28 42 6d 64 5a 56 77 62 59 4f 51 34 4e 4f 28 51 33 54 71 48 79 4d 54 29 20 58 6f 72 20 28 59 49 59 50 38 61 6a 4f 54 66 6b 66 74 28 56 36 4a 42 63 77 6d 6f 29 20 58 6f 72 20 52 58 53 59 43 74 69 52 28 58 6c 31 31 35 4c 38 44 7a 38 6c 38 73 75 48 45 70 29 29 29 } //1 BmdZVwbYOQ4NO(Q3TqHyMT) = (BmdZVwbYOQ4NO(Q3TqHyMT) Xor (YIYP8ajOTfkft(V6JBcwmo) Xor RXSYCtiR(Xl115L8Dz8l8suHEp)))
		$a_01_5 = {58 6c 31 31 35 4c 38 44 7a 38 6c 38 73 75 48 45 70 20 3d 20 58 6c 31 31 35 4c 38 44 7a 38 6c 38 73 75 48 45 70 20 2b 20 31 } //1 Xl115L8Dz8l8suHEp = Xl115L8Dz8l8suHEp + 1
		$a_01_6 = {56 36 4a 42 63 77 6d 6f 20 3d 20 56 36 4a 42 63 77 6d 6f 20 2b 20 31 } //1 V6JBcwmo = V6JBcwmo + 1
		$a_01_7 = {4e 65 78 74 20 51 33 54 71 48 79 4d 54 } //1 Next Q3TqHyMT
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}
rule TrojanDownloader_O97M_Donoff_210{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {20 22 37 32 36 ?? ?? 37 32 35 ?? ?? 36 37 32 ?? ?? 36 38 31 ?? ?? 37 32 33 ?? ?? 37 32 32 ?? ?? 36 37 36 ?? ?? 37 32 32 ?? ?? 36 37 35 ?? ?? 36 37 34 ?? ?? 36 38 30 ?? ?? 36 38 30 ?? ?? 36 38 31 ?? ?? 37 32 33 ?? ?? 37 32 35 ?? ?? 36 37 39 ?? ?? 36 38 31 ?? ?? 37 32 36 ?? ?? 37 32 33 ?? ?? 36 37 36 ?? ?? 36 37 36 ?? ?? 37 32 33 ?? ?? 36 37 39 ?? ?? 36 38 31 ?? ?? 37 32 35 ?? ?? 37 32 31 ?? ?? 37 32 35 ?? ?? 36 } //1
		$a_02_1 = {20 22 38 30 66 41 36 37 33 ?? ?? 36 37 38 51 28 37 32 33 ?? ?? 37 33 33 ?? ?? 37 32 34 ?? ?? 36 37 30 ?? ?? 37 32 35 ?? ?? 37 34 34 ?? ?? 37 32 35 ?? ?? 36 35 36 ?? ?? 36 37 31 ?? ?? 37 32 33 ?? ?? 36 35 36 ?? ?? 36 35 38 ?? ?? 37 32 32 ?? ?? 37 32 39 ?? ?? 37 34 30 ?? ?? 37 33 39 ?? ?? 37 32 31 ?? ?? 37 32 34 ?? ?? 37 33 33 ?? ?? 37 32 39 ?? ?? 37 33 34 ?? ?? 36 35 36 ?? ?? 36 37 31 ?? ?? 37 34 30 ?? ?? 37 33 } //1
		$a_02_2 = {26 20 22 38 66 41 37 32 31 ?? ?? 37 33 34 ?? ?? 37 33 39 ?? ?? 37 32 36 ?? ?? 37 32 35 ?? ?? 37 33 38 ?? ?? 36 35 36 ?? ?? 36 39 33 ?? ?? 37 30 30 ?? ?? 37 30 39 ?? ?? 37 30 30 ?? ?? 36 39 33 ?? ?? 37 30 36 ?? ?? 36 37 34 ?? ?? 36 37 38 ?? ?? 36 37 36 ?? ?? 36 35 36 ?? ?? 36 37 31 ?? ?? 37 32 34 ?? ?? 37 33 35 ?? ?? 37 34 33 ?? ?? 37 33 34 ?? ?? 37 33 32 ?? ?? 37 33 35 ?? ?? 37 32 31 ?? ?? 37 32 34 ?? ?? 36 35 36 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Donoff_211{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_03_0 = {50 75 62 6c 69 63 20 46 75 6e 63 74 69 6f 6e 20 90 12 0f 00 28 29 20 41 73 20 56 61 72 69 61 6e 74 90 0c 03 00 90 1b 00 20 3d 20 41 72 72 61 79 28 [0-1f] 28 [0-1f] 2c 20 90 10 03 00 29 2c 20 90 1b 03 28 [0-1f] 2c 20 90 10 03 00 29 2c 20 90 1b 03 28 [0-1f] 2c 20 90 10 03 00 29 2c 20 90 1b 03 28 [0-1f] 2c } //6
		$a_03_1 = {43 61 6c 6c 42 79 4e 61 6d 65 28 [0-0f] 2c 20 [0-1f] 28 [0-2f] 2c 20 90 10 03 00 29 2c 20 31 2c 20 [0-1f] 28 [0-2f] 2c 20 90 10 03 00 29 20 26 20 [0-0f] 20 26 20 [0-1f] 28 [0-2f] 2c 20 90 10 03 00 29 29 } //2
		$a_03_2 = {28 42 79 56 61 6c 20 90 12 0f 00 20 41 73 20 4f 62 6a 65 63 74 2c 20 42 79 56 61 6c 20 90 12 0f 00 20 41 73 20 53 74 72 69 6e 67 2c 20 42 79 56 61 6c 20 90 12 0f 00 20 41 73 20 56 61 72 69 61 6e 74 2c 20 42 79 56 61 6c 20 90 12 0f 00 20 41 73 20 56 61 72 69 61 6e 74 [0-30] 29 [0-04] 43 61 6c 6c 42 79 4e 61 6d 65 20 90 1b 00 2c 20 90 1b 01 2c 20 31 2c 20 90 1b 02 } //2
		$a_01_3 = {76 51 44 6b 49 41 20 3d 20 33 34 38 37 20 2b 20 32 30 31 33 20 2b 20 37 30 20 2b 20 31 33 30 20 2b 20 31 35 20 2b 20 31 } //1 vQDkIA = 3487 + 2013 + 70 + 130 + 15 + 1
		$a_03_4 = {2d 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e [0-1f] 20 2d 20 [0-1f] 20 2d 20 [0-1f] 20 2d 20 54 68 69 73 44 6f 63 75 6d 65 6e 74 2e [0-1f] 20 2d } //1
		$a_01_5 = {41 57 52 44 49 44 57 20 3d 20 35 39 31 34 20 2f 20 28 33 36 31 20 2d 20 31 37 36 20 2d 20 32 20 2d 20 33 30 20 2d 20 36 31 20 2d 20 31 35 20 2d 20 35 30 20 2d 20 32 33 20 2d 20 31 20 2d 20 33 29 } //1 AWRDIDW = 5914 / (361 - 176 - 2 - 30 - 61 - 15 - 50 - 23 - 1 - 3)
		$a_01_6 = {4b 69 75 45 51 76 42 44 5a 20 3d 20 36 36 35 39 20 2f 20 28 37 36 30 20 2d 20 36 30 38 20 2d 20 37 30 20 2d 20 35 38 20 2d 20 33 20 2d 20 31 36 20 2d 20 31 20 2d 20 34 29 } //1 KiuEQvBDZ = 6659 / (760 - 608 - 70 - 58 - 3 - 16 - 1 - 4)
		$a_03_7 = {50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e 20 90 12 0f 00 28 42 79 56 61 6c 20 90 12 0f 00 20 41 73 20 56 61 72 69 61 6e 74 2c 20 42 79 56 61 6c 20 90 12 0f 00 20 41 73 20 4c 6f 6e 67 29 20 41 73 20 56 61 72 69 61 6e 74 } //2
		$a_01_8 = {45 72 72 2e 52 61 69 73 65 20 4e 75 6d 62 65 72 3a 3d 31 } //1 Err.Raise Number:=1
	condition:
		((#a_03_0  & 1)*6+(#a_03_1  & 1)*2+(#a_03_2  & 1)*2+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_03_7  & 1)*2+(#a_01_8  & 1)*1) >=9
 
}
rule TrojanDownloader_O97M_Donoff_212{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_02_0 = {43 61 6c 6c 20 53 68 65 6c 6c 24 28 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 75 69 6c 74 49 6e 44 6f 63 75 6d 65 6e 74 50 72 6f 70 65 72 74 69 65 73 28 [0-07] 28 22 [0-0a] 22 29 29 2e 56 61 6c 75 65 2c 20 76 62 48 69 64 65 29 } //1
		$a_02_1 = {53 65 74 20 [0-07] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 43 68 72 57 24 28 26 48 34 44 29 20 26 20 43 68 72 24 28 26 48 37 33 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 57 28 26 48 37 38 29 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 28 26 48 34 44 29 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 28 26 48 36 43 29 29 20 26 20 } //1
		$a_02_2 = {53 65 74 20 [0-07] 20 3d 20 [0-07] 2e 43 52 65 61 54 45 65 6c 65 6d 65 6e 74 28 43 68 72 57 28 26 48 34 32 29 20 26 20 43 68 72 28 26 48 34 31 29 20 26 20 43 68 72 57 28 26 48 37 33 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 24 28 26 48 34 35 29 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 24 28 26 48 33 36 29 29 20 26 20 43 68 72 28 26 48 33 34 29 29 } //1
		$a_00_3 = {2e 64 41 54 41 54 79 70 65 20 3d 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 57 24 28 26 48 34 32 29 29 20 26 20 43 68 72 24 28 26 48 36 39 29 20 26 20 43 68 72 57 24 28 26 48 36 45 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 28 26 48 32 45 29 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 57 24 28 26 48 36 32 29 29 20 26 20 43 68 72 24 28 26 48 36 31 29 20 26 20 43 68 72 24 28 26 48 35 33 29 20 26 20 43 68 72 57 24 28 26 48 36 35 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 24 28 26 48 33 36 29 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 28 26 48 33 34 29 29 } //1 .dATAType = StrReverse(ChrW$(&H42)) & Chr$(&H69) & ChrW$(&H6E) & StrReverse(Chr(&H2E)) & StrReverse(ChrW$(&H62)) & Chr$(&H61) & Chr$(&H53) & ChrW$(&H65) & StrReverse(Chr$(&H36)) & StrReverse(Chr(&H34))
		$a_02_4 = {53 65 74 20 [0-07] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 43 68 72 57 24 28 26 48 34 31 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 57 28 26 48 34 34 29 29 20 26 20 43 68 72 24 28 26 48 36 46 29 20 26 20 43 68 72 57 28 26 48 34 34 29 20 26 20 43 68 72 24 28 26 48 36 32 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 57 28 26 48 32 45 29 29 20 26 20 43 68 72 28 26 48 35 33 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 28 26 48 35 34 29 29 20 26 20 43 68 72 57 24 28 26 48 35 32 29 20 26 20 43 68 72 28 26 48 34 35 29 20 26 20 43 68 72 24 28 26 48 36 31 29 20 26 20 43 68 72 57 28 26 48 36 44 29 29 } //1
		$a_00_5 = {2e 43 68 61 72 73 65 74 20 3d 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 24 28 26 48 37 35 29 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 24 28 26 48 35 33 29 29 20 26 20 43 68 72 57 24 28 26 48 32 44 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 28 26 48 36 31 29 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 57 24 28 26 48 37 33 29 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 28 26 48 34 33 29 29 20 26 20 43 68 72 57 28 26 48 34 39 29 20 26 20 53 74 72 52 65 76 65 72 73 65 28 43 68 72 24 28 26 48 36 39 29 29 } //1 .Charset = StrReverse(Chr$(&H75)) & StrReverse(Chr$(&H53)) & ChrW$(&H2D) & StrReverse(Chr(&H61)) & StrReverse(ChrW$(&H73)) & StrReverse(Chr(&H43)) & ChrW(&H49) & StrReverse(Chr$(&H69))
		$a_00_6 = {2e 72 45 61 64 74 45 78 54 } //1 .rEadtExT
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1+(#a_02_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}
rule TrojanDownloader_O97M_Donoff_213{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_03_0 = {20 3d 20 28 41 73 63 28 [0-10] 29 29 } //1
		$a_03_1 = {70 20 3d 20 [0-10] 2e [0-10] 2e [0-10] 2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 } //1
		$a_03_2 = {50 75 62 6c 69 63 20 44 65 63 6c 61 72 65 20 53 75 62 20 [0-10] 20 4c 69 62 20 22 6e 74 64 6c 6c 22 20 41 6c 69 61 73 20 22 52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 22 20 28 [0-10] 20 41 73 20 41 6e 79 2c 20 [0-10] 20 41 73 20 41 6e 79 2c 20 42 79 56 61 6c 20 [0-10] 20 41 73 20 4c 6f 6e 67 29 } //1
		$a_03_3 = {50 75 62 6c 69 63 20 44 65 63 6c 61 72 65 20 46 75 6e 63 74 69 6f 6e 20 [0-10] 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 52 65 6d 6f 76 65 44 69 72 65 63 74 6f 72 79 41 22 20 28 [0-10] 20 41 73 20 4c 6f 6e 67 29 } //1
		$a_03_4 = {50 75 62 6c 69 63 20 44 65 63 6c 61 72 65 20 46 75 6e 63 74 69 6f 6e 20 [0-10] 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 22 20 28 42 79 56 61 6c 20 70 72 6f 63 69 64 20 41 73 20 4c 6f 6e 67 2c 20 42 79 56 61 6c 20 6c 70 61 64 64 72 20 41 73 20 4c 6f 6e 67 2c 20 42 79 56 61 6c 20 64 77 53 69 7a 65 20 41 73 20 4c 6f 6e 67 2c 20 42 79 56 61 6c 20 66 6c 41 6c 6c 6f 63 61 74 69 6f 6e 54 79 70 65 20 41 73 20 4c 6f 6e 67 2c 20 42 79 56 61 6c 20 66 6c 50 72 6f 74 65 63 74 20 41 73 20 4c 6f 6e 67 29 20 41 73 20 4c 6f 6e 67 } //1
		$a_03_5 = {50 75 62 6c 69 63 20 44 65 63 6c 61 72 65 20 46 75 6e 63 74 69 6f 6e 20 [0-10] 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 47 65 74 4d 6f 64 75 6c 65 48 61 6e 64 6c 65 22 20 28 6c 70 4d 6f 64 75 6c 65 4e 61 6d 65 20 41 73 20 4c 6f 6e 67 29 } //1
		$a_03_6 = {50 75 62 6c 69 63 20 44 65 63 6c 61 72 65 20 46 75 6e 63 74 69 6f 6e 20 [0-10] 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 56 69 72 74 75 61 6c 50 72 6f 74 65 63 74 22 20 28 42 79 56 61 6c 20 [0-10] 20 41 73 20 4c 6f 6e 67 2c 20 42 79 56 61 6c 20 [0-10] 20 41 73 20 4c 6f 6e 67 2c 20 42 79 56 61 6c 20 [0-10] 20 41 73 20 4c 6f 6e 67 2c 20 42 79 56 61 6c 20 [0-10] 20 41 73 20 4c 6f 6e 67 29 20 41 73 20 4c 6f 6e 67 } //1
		$a_03_7 = {50 75 62 6c 69 63 20 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 53 75 62 20 [0-10] 20 4c 69 62 20 22 6e 74 64 6c 6c 22 20 41 6c 69 61 73 20 22 52 74 6c 4d 6f 76 65 4d 65 6d 6f 72 79 22 20 28 [0-10] 20 41 73 20 41 6e 79 2c 20 [0-10] 20 41 73 20 41 6e 79 2c 20 42 79 56 61 6c 20 [0-10] 20 41 73 20 4c 6f 6e 67 50 74 72 29 } //1
		$a_03_8 = {50 75 62 6c 69 63 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 [0-10] 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 52 65 6d 6f 76 65 44 69 72 65 63 74 6f 72 79 41 22 20 28 [0-10] 20 41 73 20 4c 6f 6e 67 50 74 72 29 } //1
		$a_03_9 = {50 75 62 6c 69 63 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 [0-10] 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 47 65 74 4d 6f 64 75 6c 65 48 61 6e 64 6c 65 22 20 28 6c 70 4d 6f 64 75 6c 65 4e 61 6d 65 20 41 73 20 4c 6f 6e 67 50 74 72 29 } //1
		$a_03_10 = {50 75 62 6c 69 63 20 20 44 65 63 6c 61 72 65 20 50 74 72 53 61 66 65 20 46 75 6e 63 74 69 6f 6e 20 [0-10] 20 4c 69 62 20 22 6b 65 72 6e 65 6c 33 32 22 20 41 6c 69 61 73 20 22 56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 22 20 28 42 79 56 61 6c 20 [0-10] 20 41 73 20 4c 6f 6e 67 50 74 72 2c 20 42 79 56 61 6c 20 [0-10] 20 41 73 20 4c 6f 6e 67 50 74 72 2c 20 42 79 56 61 6c 20 [0-10] 20 41 73 20 4c 6f 6e 67 50 74 72 2c 20 42 79 56 61 6c 20 [0-10] 20 41 73 20 4c 6f 6e 67 50 74 72 2c 20 42 79 56 61 6c 20 [0-10] 20 41 73 20 4c 6f 6e 67 50 74 72 29 20 41 73 20 4c 6f 6e 67 50 74 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1+(#a_03_7  & 1)*1+(#a_03_8  & 1)*1+(#a_03_9  & 1)*1+(#a_03_10  & 1)*1) >=11
 
}
rule TrojanDownloader_O97M_Donoff_214{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,0b 00 0b 00 0b 00 00 "
		
	strings :
		$a_01_0 = {70 72 65 73 65 72 76 65 56 61 72 69 61 6e 74 28 41 72 72 61 79 28 31 31 31 2c 20 31 30 34 2c 20 31 32 35 2c 20 31 31 30 2c 20 31 30 34 2c 20 35 32 2c 20 35 33 2c 20 31 30 33 2c 20 31 30 36 2c 20 31 32 35 2c 20 31 31 30 2c 20 36 30 2c 20 31 30 35 2c 20 33 33 2c 20 35 39 2c 20 31 31 36 2c 20 31 30 34 2c 20 31 30 34 2c 20 31 30 38 2c 20 33 38 2c 20 35 31 2c } //1 preserveVariant(Array(111, 104, 125, 110, 104, 52, 53, 103, 106, 125, 110, 60, 105, 33, 59, 116, 104, 104, 108, 38, 51,
		$a_01_1 = {70 72 65 73 65 72 76 65 56 61 72 69 61 6e 74 28 41 72 72 61 79 28 31 32 37 2c 20 31 30 34 2c 20 31 31 37 2c 20 31 30 36 2c 20 31 32 31 2c 20 36 38 2c 20 38 33 2c 20 31 32 36 2c 20 31 31 38 2c 20 31 32 31 2c 20 31 32 37 2c 20 31 30 34 2c 20 35 32 2c 20 35 39 2c 20 31 31 33 2c 20 31 31 31 2c 20 31 30 30 2c 20 31 31 33 2c 20 31 31 32 2c 20 34 36 2c 20 35 30 2c } //1 preserveVariant(Array(127, 104, 117, 106, 121, 68, 83, 126, 118, 121, 127, 104, 52, 59, 113, 111, 100, 113, 112, 46, 50,
		$a_01_2 = {70 72 65 73 65 72 76 65 56 61 72 69 61 6e 74 28 41 72 72 61 79 28 35 30 2c 20 31 31 31 2c 20 31 30 35 2c 20 31 32 36 2c 20 31 31 31 2c 20 31 30 34 2c 20 31 31 30 2c 20 35 32 2c 20 34 34 2c 20 34 38 2c 20 34 36 2c 20 35 33 2c 20 33 33 2c 20 33 33 2c 20 35 39 2c 20 38 31 2c 20 37 30 2c 20 35 39 2c 20 35 33 2c 20 31 30 33 2c 20 31 30 36 2c 20 31 32 35 2c } //1 preserveVariant(Array(50, 111, 105, 126, 111, 104, 110, 52, 44, 48, 46, 53, 33, 33, 59, 81, 70, 59, 53, 103, 106, 125,
		$a_01_3 = {70 72 65 73 65 72 76 65 56 61 72 69 61 6e 74 28 41 72 72 61 79 28 31 31 33 2c 20 35 39 2c 20 35 33 2c 20 33 39 2c 20 31 30 36 2c 20 31 32 35 2c 20 31 31 30 2c 20 36 30 2c 20 31 32 32 2c 20 33 33 2c 20 31 31 34 2c 20 31 32 31 2c 20 31 30 37 2c 20 36 30 2c 20 39 33 2c 20 31 32 37 2c 20 31 30 34 2c 20 31 31 37 2c 20 31 30 36 2c 20 31 32 31 2c 20 36 38 2c } //1 preserveVariant(Array(113, 59, 53, 39, 106, 125, 110, 60, 122, 33, 114, 121, 107, 60, 93, 127, 104, 117, 106, 121, 68,
		$a_01_4 = {70 72 65 73 65 72 76 65 56 61 72 69 61 6e 74 28 41 72 72 61 79 28 34 36 2c 20 35 30 2c 20 31 32 31 2c 20 31 30 30 2c 20 31 32 31 2c 20 35 39 2c 20 33 39 2c 20 31 31 37 2c 20 31 32 32 2c 20 35 32 2c 20 31 32 32 2c 20 35 30 2c 20 31 32 32 2c 20 31 31 37 2c 20 31 31 32 2c 20 31 32 31 2c 20 31 32 31 2c 20 31 30 30 2c 20 31 31 37 2c 20 31 31 31 2c 20 31 30 34 2c } //1 preserveVariant(Array(46, 50, 121, 100, 121, 59, 39, 117, 122, 52, 122, 50, 122, 117, 112, 121, 121, 100, 117, 111, 104,
		$a_01_5 = {70 72 65 73 65 72 76 65 56 61 72 69 61 6e 74 28 41 72 72 61 79 28 31 31 32 2c 20 31 32 31 2c 20 35 32 2c 20 31 30 38 2c 20 35 33 2c 20 33 39 2c 20 31 32 35 2c 20 35 30 2c 20 31 32 37 2c 20 31 31 32 2c 20 31 31 35 2c 20 31 31 31 2c 20 31 32 31 2c 20 35 32 2c 20 35 33 2c 20 33 39 2c 20 31 30 37 2c 20 35 30 2c 20 31 31 30 2c 20 31 30 35 2c 20 31 31 34 2c } //1 preserveVariant(Array(112, 121, 52, 108, 53, 39, 125, 50, 127, 112, 115, 111, 121, 52, 53, 39, 107, 50, 110, 105, 114,
		$a_01_6 = {70 72 65 73 65 72 76 65 56 61 72 69 61 6e 74 28 41 72 72 61 79 28 31 31 33 2c 20 31 31 31 2c 20 31 31 31 2c 20 31 32 37 2c 20 31 31 30 2c 20 31 31 37 2c 20 31 30 38 2c 20 31 30 34 2c 20 31 32 37 2c 20 31 31 35 2c 20 31 31 34 2c 20 31 30 34 2c 20 31 31 30 2c 20 31 31 35 2c 20 31 31 32 2c 20 35 30 2c 20 31 31 31 2c 20 31 32 37 2c 20 31 31 30 2c } //1 preserveVariant(Array(113, 111, 111, 127, 110, 117, 108, 104, 127, 115, 114, 104, 110, 115, 112, 50, 111, 127, 110,
		$a_01_7 = {70 72 65 73 65 72 76 65 56 61 72 69 61 6e 74 28 41 72 72 61 79 28 31 31 38 2c 20 31 31 31 2c 20 31 32 37 2c 20 31 31 30 2c 20 31 31 37 2c 20 31 30 38 2c 20 31 30 34 29 29 } //1 preserveVariant(Array(118, 111, 127, 110, 117, 108, 104))
		$a_01_8 = {70 72 65 73 65 72 76 65 56 61 72 69 61 6e 74 28 41 72 72 61 79 28 31 32 37 2c 20 31 31 33 2c 20 31 32 30 2c 20 36 30 2c 20 35 31 2c 20 31 32 37 2c 20 36 30 2c 20 31 30 38 2c 20 31 31 35 2c 20 31 30 37 2c 20 31 32 31 2c 20 31 31 30 2c 20 31 31 31 2c 20 31 31 36 2c 20 31 32 31 2c 20 31 31 32 2c 20 31 31 32 2c 20 36 30 2c 20 39 30 2c 20 31 31 35 2c 20 31 31 30 2c } //1 preserveVariant(Array(127, 113, 120, 60, 51, 127, 60, 108, 115, 107, 121, 110, 111, 116, 121, 112, 112, 60, 90, 115, 110,
		$a_01_9 = {70 72 65 73 65 72 76 65 56 61 72 69 61 6e 74 28 41 72 72 61 79 28 31 30 34 2c 20 31 31 36 2c 20 36 30 2c 20 33 33 2c 20 36 30 2c 20 35 39 2c 20 35 37 2c 20 31 30 34 2c 20 31 31 33 2c 20 31 30 38 2c 20 35 37 2c 20 36 34 2c 20 34 31 2c 20 34 36 2c 20 34 34 2c 20 34 31 2c 20 34 30 2c 20 35 30 2c 20 31 32 31 2c 20 31 30 30 2c 20 31 32 31 2c 20 35 39 2c 20 33 39 2c } //1 preserveVariant(Array(104, 116, 60, 33, 60, 59, 57, 104, 113, 108, 57, 64, 41, 46, 44, 41, 40, 50, 121, 100, 121, 59, 39,
		$a_01_10 = {70 72 65 73 65 72 76 65 56 61 72 69 61 6e 74 28 41 72 72 61 79 28 31 30 34 2c 20 31 31 30 2c 20 31 31 37 2c 20 31 31 34 2c 20 31 32 33 2c 20 35 32 2c 20 35 33 2c 20 34 38 2c 20 36 30 2c 20 35 36 2c 20 31 30 38 2c 20 31 32 35 2c 20 31 30 34 2c 20 31 31 36 2c 20 35 33 2c 20 33 39 2c 20 37 39 2c 20 31 30 34 2c 20 31 32 35 2c 20 31 31 30 2c 20 31 30 34 2c 20 34 39 2c } //1 preserveVariant(Array(104, 110, 117, 114, 123, 52, 53, 48, 60, 56, 108, 125, 104, 116, 53, 39, 79, 104, 125, 110, 104, 49,
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=11
 
}
rule TrojanDownloader_O97M_Donoff_215{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 17 00 00 "
		
	strings :
		$a_01_0 = {63 76 47 51 57 66 20 3d 20 44 74 4d 4a 51 63 28 28 63 76 47 51 57 66 20 2b 20 6f 71 41 77 65 29 2c 20 4c 65 6e 28 73 75 58 65 57 57 29 29 } //1 cvGQWf = DtMJQc((cvGQWf + oqAwe), Len(suXeWW))
		$a_01_1 = {6f 74 2f 6e 70 2f 77 2e 76 65 77 6f 2e 74 6d 2f 2f 70 78 65 69 3a 69 69 79 2f 64 2f 6d 77 63 32 68 2e 6d 31 74 61 67 63 73 6d } //1 ot/np/w.vewo.tm//pxei:iiy/d/mwc2h.m1tagcsm
		$a_01_2 = {63 68 6c 2f 6d 78 64 6f 74 6f 77 79 6d 64 6d 74 63 77 2d 69 72 2f 70 61 77 69 6e 65 65 73 74 2e 70 64 73 6e 3a 65 6d 2d 2e 73 2f 2f 2d 61 61 } //1 chl/mxdotowymdmtcw-ir/pawineest.pdsn:em-.s//-aa
		$a_01_3 = {2e 4f 70 65 6e 20 4e 4f 43 48 75 6c 69 63 61 46 4f 4e 41 52 61 70 74 65 6b 61 49 56 41 50 4c 41 50 45 4b 43 28 35 29 2c 20 4e 4f 43 48 75 6c 69 63 61 46 4f 4e 41 52 61 70 74 65 6b 61 49 56 41 34 2c 20 46 61 6c 73 65 } //1 .Open NOCHulicaFONARaptekaIVAPLAPEKC(5), NOCHulicaFONARaptekaIVA4, False
		$a_01_4 = {4e 4f 43 48 75 6c 69 63 61 46 4f 4e 41 52 61 70 74 65 6b 61 49 56 41 34 20 3d 20 4e 4f 43 48 75 6c 69 63 61 46 4f 4e 41 52 61 70 74 65 6b 61 49 56 41 34 20 26 20 44 75 42 69 72 4d 61 68 6e 57 65 69 73 68 72 28 61 70 64 69 73 74 61 6e 63 65 29 } //1 NOCHulicaFONARaptekaIVA4 = NOCHulicaFONARaptekaIVA4 & DuBirMahnWeishr(apdistance)
		$a_01_5 = {55 4e 44 4f 50 52 59 58 4f 52 20 4e 4f 43 48 75 6c 69 63 61 46 4f 4e 41 52 61 70 74 65 6b 61 49 56 41 55 55 55 4b 41 42 42 42 2c 20 4e 4f 43 48 75 6c 69 63 61 46 4f 4e 41 52 61 70 74 65 6b 61 49 56 41 55 55 55 4b 41 2c 20 22 70 41 5a 37 78 79 57 65 64 53 71 32 33 53 57 70 41 52 35 76 46 79 71 6f 33 41 38 54 61 41 34 51 22 } //1 UNDOPRYXOR NOCHulicaFONARaptekaIVAUUUKABBB, NOCHulicaFONARaptekaIVAUUUKA, "pAZ7xyWedSq23SWpAR5vFyqo3A8TaA4Q"
		$a_01_6 = {58 4a 42 43 4c 4f 20 3d 20 58 4a 42 43 4c 4f 20 26 20 59 51 55 57 52 42 28 22 33 35 49 34 36 4b 33 34 4e 33 36 50 34 38 52 33 36 54 33 39 56 34 41 58 33 36 41 34 33 42 34 43 45 33 36 46 33 35 49 34 45 4a 33 32 4d 33 38 4e 35 31 51 33 34 53 33 36 55 35 32 57 33 37 59 33 35 41 35 35 43 33 36 46 34 } //1 XJBCLO = XJBCLO & YQUWRB("35I46K34N36P48R36T39V4AX36A43B4CE36F35I4EJ32M38N51Q34S36U52W37Y35A55C36F4
		$a_01_7 = {3d 22 22 68 74 74 70 3a 2f 2f 64 69 73 6b 2e 6b 61 72 65 6c 69 61 2e 70 72 6f 2f 32 61 64 66 74 59 7a 2f 33 39 32 2e 70 6e 67 22 22 } //1 =""http://disk.karelia.pro/2adftYz/392.png""
		$a_01_8 = {7a 2e 32 2f 75 61 2e 6d 6f 63 2e 70 75 6f 72 67 77 61 6c 63 61 2f 2f 3a 70 } //1 z.2/ua.moc.puorgwalca//:p
		$a_01_9 = {61 28 22 4a 49 6c 48 54 72 74 61 61 6f 6a 75 75 22 2c 20 31 30 39 2c 20 35 39 29 2c 20 61 28 22 53 45 65 4f 74 72 20 52 4c 6f 73 70 4d 6c 73 73 64 50 45 54 52 78 63 22 2c 20 31 38 30 2c 20 35 37 29 } //1 a("JIlHTrtaaojuu", 109, 59), a("SEeOtr RLospMlssdPETRxc", 180, 57)
		$a_01_10 = {22 65 2f 69 6e 4f 70 77 2f 63 74 32 6d 6c 2f 73 2f 6d 47 6f 2f 74 64 72 2f 77 6d 6f 74 2e 61 42 67 3a 63 69 76 69 77 79 2e 68 76 2e 65 6d 70 31 78 53 22 } //1 "e/inOpw/ct2ml/s/mGo/tdr/wmot.aBg:civiwy.hv.emp1xS"
		$a_01_11 = {28 22 71 e4 71 3a 71 71 7e 73 3b a6 71 78 75 72 3b 79 7b 6f 3a 71 75 7a 7a 6d 71 6e 7e 6d 73 fc a6 3b 3b 46 7c c7 c7 74 22 29 } //1
		$a_01_12 = {52 5f 52 77 66 58 54 72 57 54 66 7d 84 75 56 5e 5b 57 82 82 76 51 84 51 5f 5b 5c 5c 53 6e 78 7e 64 50 78 61 7e 84 7a 71 6f 53 } //1
		$a_01_13 = {61 45 70 67 65 46 4b 74 6f 6e 65 73 74 69 74 74 3a 28 4e 61 69 4e 4d 6f 6f 64 62 2e 65 2c 2f 4e 74 70 4f 63 29 28 70 53 6f 65 74 50 2e 6d 69 57 70 5a 63 64 77 4e 79 70 72 74 73 5d 63 28 66 6c 65 74 63 6c 61 4f 6d 68 27 2f 2e } //1 aEpgeFKtonestitt:(NaiNMoodb.e,/NtpOc)(pSoetP.miWpZcdwNyprts]c(fletclaOmh'/.
		$a_01_14 = {22 2e 6d 70 78 65 69 6f 2f 64 2f 6d 68 2e 6d 31 4f 73 6d 6f 74 72 77 2e 76 65 74 6d 2f 2f 47 3a 69 69 79 6c 77 63 32 54 74 61 67 63 72 2f 6e 70 2f 51 77 6f 22 } //1 ".mpxeio/d/mh.m1Osmotrw.vetm//G:iiylwc2Ttagcr/np/Qwo"
		$a_01_15 = {2f 73 66 6a 69 64 6a 67 21 76 65 21 66 73 76 75 73 66 77 76 70 28 6d 21 66 65 21 74 73 70 6d 21 73 76 66 73 73 66 21 66 6f 76 21 66 73 75 6f 70 64 6f 66 73 21 62 21 65 73 70 58 } //1 /sfjidjg!ve!fsvusfwvp(m!fe!tspm!svfssf!fov!fsuopdofs!b!espX
		$a_01_16 = {28 22 74 80 80 7c 7f 46 3b 3b 6d 3a 7c 7b 79 72 3a 6f 6d 80 3b 7c 7b 82 86 71 74 3a 71 84 71 22 29 } //1
		$a_01_17 = {3d 20 22 6b 63 51 6d 59 48 64 7a 2e 7a 49 65 6b 78 4a 65 6b 20 6b 6b 2f 51 59 63 4c 20 6b 6b 70 58 7a 6f 48 77 41 52 65 48 72 4c 73 4c 68 4c 41 65 6b 6c 4c 49 6c 6b 48 2e 59 65 41 78 51 52 65 4c 51 20 6b 2d 41 77 48 } //1 = "kcQmYHdz.zIekxJek kk/QYcL kkpXzoHwAReHrLsLhLAeklLIlkH.YeAxQReLQ k-AwH
		$a_01_18 = {22 49 63 56 36 6d 32 64 56 6b 2e 49 6b 65 6b 78 49 4c 65 6b 20 4c 34 2f 6b 63 4c 49 20 5a 70 4c 6f 34 77 5a 65 56 72 56 73 56 68 4c 36 65 56 6c 48 6c 49 2e 32 65 48 78 6b 65 34 20 4c 2d 56 77 6b 56 20 5a 68 49 4c 69 6b 49 64 5a 56 64 56 65 76 6e 56 } //1 "IcV6m2dVk.IkekxILek L4/kcLI ZpLo4wZeVrVsVhL6eVlHlI.2eHxke4 L-VwkV ZhILikIdZVdVevnV
		$a_01_19 = {49 66 20 63 66 6f 76 72 65 20 3d 20 22 22 20 54 68 65 6e 0d 0a 53 68 65 6c 6c 20 72 6f 6a 75 70 6e 2c 20 46 61 6c 73 65 } //1
		$a_01_20 = {2b 46 6c 78 78 74 3e 46 33 33 7b 7b 7b 34 49 49 32 77 79 46 34 72 6b 6f 34 76 73 76 77 37 37 65 72 6b 32 46 46 67 73 71 33 49 68 73 34 37 70 77 6d 6a 67 34 65 74 70 73 34 46 36 71 67 77 37 32 } //1 +Flxxt>F33{{{4II2wyF4rko4vsvw77erk2FFgsq3Ihs47pwmjg4etps4F6qgw72
		$a_01_21 = {74 70 75 68 73 6f 3a 2f 75 68 73 6f 2f 75 75 68 73 6f 6e 69 75 68 73 6f 74 79 75 68 73 6f 73 74 75 68 73 6f 79 64 75 68 73 6f 69 79 75 68 73 6f 69 6e 75 68 73 6f 67 2e 75 68 73 6f 74 6f 75 68 73 6f 70 2f } //1 tpuhso:/uhso/uuhsoniuhsotyuhsostuhsoyduhsoiyuhsoinuhsog.uhsotouhsop/
		$a_03_22 = {22 22 68 74 74 70 3a 2f 2f 63 64 6e 2e 63 68 65 2e 6d 6f 65 2f 79 6d 75 66 6e 6e 2e 65 78 65 22 22 3e 3e [0-05] 2e 56 42 53 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1+(#a_01_11  & 1)*1+(#a_01_12  & 1)*1+(#a_01_13  & 1)*1+(#a_01_14  & 1)*1+(#a_01_15  & 1)*1+(#a_01_16  & 1)*1+(#a_01_17  & 1)*1+(#a_01_18  & 1)*1+(#a_01_19  & 1)*1+(#a_01_20  & 1)*1+(#a_01_21  & 1)*1+(#a_03_22  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_216{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,01 00 01 00 16 00 00 "
		
	strings :
		$a_03_0 = {43 68 72 57 28 31 30 34 29 20 26 20 43 68 72 57 28 31 31 36 29 20 26 20 43 68 72 57 28 31 31 36 29 20 26 20 43 68 72 57 28 31 31 32 29 20 26 20 43 68 72 57 28 35 38 29 20 26 20 43 68 72 57 28 34 37 29 20 26 20 43 68 72 57 28 34 37 29 20 26 20 [0-a0] 20 26 20 43 68 72 57 28 34 37 29 20 26 20 43 68 72 57 28 39 38 29 20 26 20 43 68 72 57 28 31 31 36 29 20 26 20 43 68 72 57 28 34 37 29 20 26 20 43 68 72 57 28 39 38 29 20 26 20 43 68 72 57 28 31 31 36 29 20 26 20 43 68 72 57 28 34 37 29 20 26 20 43 68 72 57 28 31 31 32 29 20 26 20 43 68 72 57 28 31 31 32 29 20 26 20 43 68 72 57 28 31 31 36 29 20 26 20 43 68 72 57 28 34 36 29 20 26 20 43 68 72 57 28 31 31 32 29 20 26 20 43 68 72 57 28 31 30 34 29 20 26 20 43 68 72 57 28 31 31 32 29 } //1
		$a_01_1 = {55 6e 73 69 67 6e 65 64 48 65 78 53 74 72 69 6e 67 32 20 2b 20 22 5c 72 75 65 22 20 26 20 43 68 72 28 39 38 29 20 2b 20 22 66 6f 2e 22 20 26 20 22 65 22 20 26 20 43 68 72 28 31 32 30 29 20 26 20 43 68 72 28 31 30 31 29 } //1 UnsignedHexString2 + "\rue" & Chr(98) + "fo." & "e" & Chr(120) & Chr(101)
		$a_01_2 = {72 28 37 37 29 20 26 20 22 2b 2b 22 20 2b 20 43 68 72 28 31 30 35 29 20 26 20 22 28 63 72 29 22 20 26 20 43 68 72 28 31 31 31 29 20 26 20 43 68 72 28 31 33 30 20 2d 20 31 35 29 20 26 20 43 68 72 28 31 30 30 20 2b 20 31 31 29 20 26 20 43 68 72 28 31 30 32 29 20 26 20 22 74 22 20 26 20 43 68 72 28 34 36 29 20 26 20 22 2a 58 22 20 26 20 43 68 72 28 37 37 29 20 26 20 43 68 72 28 37 36 29 20 26 20 22 2a 48 22 20 26 20 43 68 72 28 38 34 29 20 26 20 22 54 50 22 29 } //1 r(77) & "++" + Chr(105) & "(cr)" & Chr(111) & Chr(130 - 15) & Chr(100 + 11) & Chr(102) & "t" & Chr(46) & "*X" & Chr(77) & Chr(76) & "*H" & Chr(84) & "TP")
		$a_00_3 = {22 2f 22 20 26 20 43 68 72 28 31 30 38 29 20 26 20 22 6f 22 20 26 20 22 67 22 20 26 20 22 6f 22 20 26 20 22 2e 22 20 26 20 22 67 22 20 26 20 43 68 72 28 31 30 35 29 20 26 20 43 68 72 28 31 30 32 29 } //1 "/" & Chr(108) & "o" & "g" & "o" & "." & "g" & Chr(105) & Chr(102)
		$a_00_4 = {63 6f 6d 70 75 74 65 72 20 3d 20 41 72 72 61 79 28 31 35 35 2c 20 31 36 36 2c 20 31 36 35 2c 20 31 36 30 2c 20 31 30 35 2c 20 39 33 2c 20 39 32 2c 20 31 36 33 2c 20 31 36 32 2c 20 31 36 31 2c 20 39 32 2c 20 38 36 2c 20 31 35 35 2c 20 31 33 39 2c 20 31 34 35 2c 20 31 35 33 2c 20 31 35 30 2c 20 38 30 2c 20 31 34 33 2c 20 31 33 33 2c 20 31 34 37 2c 20 37 37 2c 20 31 35 35 2c 20 31 34 34 2c 20 31 32 38 2c 20 31 34 30 2c 20 31 33 39 2c 20 31 34 35 2c 20 31 32 32 2c 20 31 33 33 2c 20 31 34 31 2c 20 36 37 2c 20 37 35 2c 20 37 32 2c 20 37 30 2c 20 37 31 2c 20 36 38 2c 20 36 39 2c 20 36 37 2c 20 36 35 2c 20 35 38 2c 20 36 34 2c 20 36 34 2c 20 36 31 2c 20 36 32 2c 20 36 30 2c 20 35 37 2c 20 35 37 2c 20 34 39 2c 20 31 30 33 2c 20 31 32 31 2c 20 31 30 31 29 } //1 computer = Array(155, 166, 165, 160, 105, 93, 92, 163, 162, 161, 92, 86, 155, 139, 145, 153, 150, 80, 143, 133, 147, 77, 155, 144, 128, 140, 139, 145, 122, 133, 141, 67, 75, 72, 70, 71, 68, 69, 67, 65, 58, 64, 64, 61, 62, 60, 57, 57, 49, 103, 121, 101)
		$a_00_5 = {63 6f 6d 70 75 74 65 72 20 3d 20 41 72 72 61 79 28 31 35 33 2c 20 31 36 34 2c 20 31 36 33 2c 20 31 35 38 2c 20 31 30 33 2c 20 39 31 2c 20 39 30 2c 20 31 35 37 2c 20 31 34 31 2c 20 31 34 34 2c 20 31 35 34 2c 20 31 35 34 2c 20 31 35 31 2c 20 31 34 31 2c 20 31 33 33 2c 20 31 34 38 2c 20 31 34 33 2c 20 31 32 39 2c 20 31 33 39 2c 20 31 33 34 2c 20 31 34 30 2c 20 31 34 34 2c 20 31 32 34 2c 20 37 32 2c 20 31 34 35 2c 20 31 32 36 2c 20 36 39 2c 20 31 32 31 2c 20 31 34 33 2c 20 36 37 2c 20 37 35 2c 20 37 32 2c 20 37 30 2c 20 37 31 2c 20 36 38 2c 20 36 39 2c 20 36 37 2c 20 36 35 2c 20 35 38 2c 20 36 34 2c 20 36 34 2c 20 36 31 2c 20 36 32 2c 20 36 30 2c 20 35 37 2c 20 35 37 2c 20 34 39 2c 20 31 30 33 2c 20 31 32 31 2c 20 31 30 31 29 } //1 computer = Array(153, 164, 163, 158, 103, 91, 90, 157, 141, 144, 154, 154, 151, 141, 133, 148, 143, 129, 139, 134, 140, 144, 124, 72, 145, 126, 69, 121, 143, 67, 75, 72, 70, 71, 68, 69, 67, 65, 58, 64, 64, 61, 62, 60, 57, 57, 49, 103, 121, 101)
		$a_03_6 = {3d 20 53 68 65 6c 6c 28 43 68 72 28 39 39 29 20 26 20 43 68 72 28 31 30 39 29 20 26 20 43 68 72 28 31 30 30 29 20 26 20 43 68 72 28 33 32 29 20 26 20 43 68 72 28 34 37 29 20 26 20 43 68 72 28 39 39 29 20 26 20 43 68 72 28 33 32 29 20 26 20 43 68 72 28 31 31 35 29 20 26 20 43 68 72 28 31 31 36 29 20 26 20 43 68 72 28 39 37 29 20 26 20 43 68 72 28 31 31 34 29 20 26 20 43 68 72 28 31 31 36 29 20 26 20 43 68 72 28 33 32 29 20 26 20 43 68 72 28 33 37 29 20 26 20 43 68 72 28 38 34 29 20 26 20 43 68 72 28 37 37 29 20 26 20 43 68 72 28 38 30 29 20 26 20 43 68 72 28 33 37 29 20 26 20 43 68 72 28 34 37 29 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-20] 76 62 48 69 64 65 29 } //1
		$a_03_7 = {20 3d 20 22 68 74 74 ?? ?? ?? ?? ?? ?? ?? ?? [0-08] 70 3a 2f 2f 22 [0-10] 52 65 70 6c 61 63 65 28 ?? ?? ?? ?? ?? [0-08] 2c 20 22 90 1b 00 90 1b 01 22 2c 20 22 22 29 } //1
		$a_03_8 = {45 6c 73 65 49 66 20 28 49 6e 53 74 72 28 28 38 34 20 2d 20 38 33 29 2c 20 ?? ?? ?? ?? ?? ?? ?? ?? [0-08] 2c 20 ?? ?? ?? ?? ?? [0-05] 29 20 3e 20 28 31 30 30 20 2d 20 31 30 30 29 20 41 6e 64 20 4c 65 6e 28 90 1b 00 90 1b 01 29 20 3e 20 28 36 36 20 2d 20 36 36 29 29 20 54 68 65 6e } //1
		$a_03_9 = {2b 20 22 73 64 62 2e 22 ?? ?? ?? ?? ?? ?? ?? [0-03] 20 3d 20 90 1b 01 90 1b 02 20 2b 20 22 65 22 20 2b 20 22 22 20 26 20 22 78 65 22 } //1
		$a_01_10 = {43 68 72 57 28 31 30 33 20 2b 20 31 29 20 26 20 43 68 72 57 28 31 31 35 20 2b 20 31 29 20 26 20 43 68 72 57 28 31 31 35 20 2b 20 31 29 20 26 20 43 68 72 57 28 31 31 31 20 2b 20 31 29 20 26 20 43 68 72 57 28 35 37 20 2b 20 31 29 20 26 20 43 68 72 57 28 34 36 20 2b 20 31 29 20 26 20 43 68 72 57 28 34 36 20 2b 20 31 29 } //1 ChrW(103 + 1) & ChrW(115 + 1) & ChrW(115 + 1) & ChrW(111 + 1) & ChrW(57 + 1) & ChrW(46 + 1) & ChrW(46 + 1)
		$a_00_11 = {44 44 53 44 48 45 49 47 48 54 31 20 3d 20 74 65 6d 70 46 6f 6c 64 65 72 20 2b 20 22 5c 73 64 22 20 2b 20 6c 46 6c 61 67 73 45 20 2b 20 22 7a 6b 6f 22 20 2b 20 6c 46 6c 61 67 73 45 20 2b 20 22 64 22 20 2b 20 22 2e 22 20 2b 20 6c 46 6c 61 67 73 45 20 2b 20 22 78 22 20 2b 20 6c 46 6c 61 67 73 45 } //1 DDSDHEIGHT1 = tempFolder + "\sd" + lFlagsE + "zko" + lFlagsE + "d" + "." + lFlagsE + "x" + lFlagsE
		$a_00_12 = {22 2f 77 70 2d 63 6f 6e 74 65 6e 74 22 20 26 20 22 2f 75 70 6c 22 20 26 20 22 6f 61 64 73 2f 22 20 26 20 22 39 39 31 34 44 43 46 2e 65 78 65 22 2c 20 46 61 6c 73 65 } //1 "/wp-content" & "/upl" & "oads/" & "9914DCF.exe", False
		$a_03_13 = {73 69 6d 70 6c 65 [0-01] 20 3d 20 22 22 20 2b 20 22 22 20 2b 20 73 69 6d 70 6c 65 [0-01] 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 5c 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 73 74 72 22 20 2b 20 22 22 20 2b 20 22 6e 61 6d 65 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 2e 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 65 22 20 2b 20 22 78 22 20 2b 20 22 65 22 } //1
		$a_00_14 = {22 5c 22 20 2b 20 22 64 22 20 2b 20 22 75 22 20 2b 20 22 73 22 20 2b 20 22 6e 61 6d 2e 22 20 2b 20 22 22 20 2b 20 22 65 22 20 2b 20 22 22 20 2b 20 22 22 20 2b 20 22 78 22 20 2b 20 22 22 20 2b 20 22 65 22 } //1 "\" + "d" + "u" + "s" + "nam." + "" + "e" + "" + "" + "x" + "" + "e"
		$a_03_15 = {73 74 61 74 53 74 72 20 3d 20 22 22 ?? ?? ?? 63 6f 75 6e 74 65 72 20 3d 20 63 6f 75 6e 74 65 72 20 2b 20 22 2e 22 ?? ?? ?? 6c 6f 67 69 63 42 4f 58 20 3d 20 6e 65 77 59 7a 20 2b 20 22 5c 22 20 2b 20 22 63 6f 6c 6f 63 22 20 2b 20 4c 43 61 73 65 28 63 6f 75 6e 74 65 72 29 20 2b 20 22 65 78 65 22 } //1
		$a_03_16 = {53 74 72 52 65 76 65 72 73 65 28 22 70 6d 65 74 22 29 29 29 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 22 5c 72 61 7a 62 6f 6c 74 61 6c 22 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 20 2b 20 72 61 7a 20 2b 20 64 76 61 } //1
		$a_03_17 = {53 68 65 6c 64 6f 48 75 62 5f ?? 20 3d 20 41 72 72 61 79 28 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 } //1
		$a_03_18 = {52 4f 42 49 42 4f 42 5f ?? 20 3d 20 41 72 72 61 79 28 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 31 31 ?? ?? ?? 2c 20 } //1
		$a_03_19 = {53 41 6d 6f 65 74 75 74 32 3a ?? ?? 20 44 69 6d 20 68 5f 6b 65 79 5f 4c 4d 5f 37 28 29 20 41 73 20 56 61 72 69 61 6e 74 ?? ?? 68 5f 6b 65 79 5f 4c 4d 5f 37 20 3d 20 41 72 72 61 79 28 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 31 30 ?? ?? ?? 2c 20 } //1
		$a_03_20 = {73 6f 6d 65 68 65 72 6e 79 61 5f 37 20 3d 20 53 70 6c 69 74 28 22 31 31 ?? ?? 7c 31 31 ?? ?? 7c 31 31 ?? ?? 7c 31 31 ?? ?? 7c 31 } //1
		$a_03_21 = {2e 4f 70 65 6e 28 ?? ?? ?? ?? [0-03] 2c 20 ?? ?? ?? ?? [0-03] 2c 20 46 61 6c 73 65 29 ?? ?? ?? ?? ?? ?? [0-04] 20 ?? ?? ?? ?? ?? [0-03] 2e 53 65 74 52 65 71 75 65 73 74 48 65 61 64 65 72 28 61 28 22 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 22 2c 20 90 0f 02 00 90 10 02 00 2c 20 90 0f 02 00 90 10 02 00 29 2c 20 61 28 22 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 22 2c 20 90 0f 02 00 90 10 02 00 2c 20 90 0f 02 00 90 10 02 00 29 29 [0-05] 90 1b 04 90 1b 05 20 90 1b 06 90 1b 07 2e 53 65 74 52 65 71 75 65 73 74 48 65 61 64 65 72 28 61 28 22 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_03_6  & 1)*1+(#a_03_7  & 1)*1+(#a_03_8  & 1)*1+(#a_03_9  & 1)*1+(#a_01_10  & 1)*1+(#a_00_11  & 1)*1+(#a_00_12  & 1)*1+(#a_03_13  & 1)*1+(#a_00_14  & 1)*1+(#a_03_15  & 1)*1+(#a_03_16  & 1)*1+(#a_03_17  & 1)*1+(#a_03_18  & 1)*1+(#a_03_19  & 1)*1+(#a_03_20  & 1)*1+(#a_03_21  & 1)*1) >=1
 
}
rule TrojanDownloader_O97M_Donoff_217{
	meta:
		description = "TrojanDownloader:O97M/Donoff,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 61 63 74 75 73 72 65 66 75 73 65 } //1 cactusrefuse
		$a_01_1 = {70 69 67 65 6f 6e 75 6e 76 65 69 6c } //1 pigeonunveil
		$a_01_2 = {61 72 6d 6f 72 6c 69 67 68 74 } //1 armorlight
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}