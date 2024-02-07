
rule TrojanDownloader_O97M_Ursnif_PKY_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.PKY!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {44 65 63 6f 64 65 42 61 73 65 36 34 28 28 62 75 6d 65 72 61 6e 67 75 73 28 61 72 4d 61 6e 69 28 22 35 3b 36 68 2d 74 32 30 74 20 70 36 73 20 3a 22 29 20 26 20 22 3a 2f 2f 22 20 26 20 61 72 4d 61 6e 69 28 22 6d 65 64 65 72 61 6f 67 73 22 29 20 26 20 22 2e 22 20 26 20 61 72 4d 61 6e 69 28 22 2f 63 31 32 6f 2d 6d 22 29 29 29 29 2c 20 46 61 72 6d 61 63 69 } //01 00  DecodeBase64((bumerangus(arMani("5;6h-t20t p6s :") & "://" & arMani("mederaogs") & "." & arMani("/c12o-m")))), Farmaci
		$a_01_1 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 44 65 66 61 75 6c 74 46 69 6c 65 50 61 74 68 } //01 00  Application.DefaultFilePath
		$a_01_2 = {50 72 69 76 61 74 65 20 46 75 6e 63 74 69 6f 6e 20 44 65 63 6f 64 65 42 61 73 65 36 34 28 73 74 72 44 61 74 61 29 } //01 00  Private Function DecodeBase64(strData)
		$a_01_3 = {3d 20 44 6f 6e 61 74 69 20 26 20 61 72 4d 61 6e 69 28 22 30 5c 39 63 36 61 6c 39 63 22 29 20 26 20 22 2e 22 20 26 20 61 72 4d 61 6e 69 28 22 39 65 37 2d 78 35 65 22 29 } //00 00  = Donati & arMani("0\9c6al9c") & "." & arMani("9e7-x5e")
	condition:
		any of ($a_*)
 
}