
rule TrojanDownloader_MacOS_AdLoad_D_MTB{
	meta:
		description = "TrojanDownloader:MacOS/AdLoad.D!MTB,SIGNATURE_TYPE_MACHOHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_00_0 = {2f 43 6f 6e 74 65 6e 74 73 2f 52 65 73 6f 75 72 63 65 73 2f 77 69 63 2e 70 6e 67 } //01 00  /Contents/Resources/wic.png
		$a_03_1 = {44 8b 68 04 48 89 df e8 90 01 03 00 48 85 c0 74 dc 8a 18 84 db 74 d6 41 83 c5 07 41 83 e5 f8 4c 89 f9 4c 29 e9 48 c1 e9 03 31 d2 90 00 } //01 00 
		$a_01_2 = {2f 43 6f 6e 74 65 6e 74 73 2f 52 65 73 6f 75 72 63 65 73 2f 77 69 63 2e 70 6e 67 } //00 00  /Contents/Resources/wic.png
	condition:
		any of ($a_*)
 
}