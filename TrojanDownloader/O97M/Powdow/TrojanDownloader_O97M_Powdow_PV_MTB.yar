
rule TrojanDownloader_O97M_Powdow_PV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_00_0 = {3d 20 6a 6b 6a 75 7a 69 78 66 71 6b 75 64 67 20 26 20 22 2e 6e 65 74 22 } //01 00  = jkjuzixfqkudg & ".net"
		$a_00_1 = {3d 20 22 70 6f 7a 78 6d 63 6a 73 6e 71 77 65 61 73 6a 61 73 64 61 2e 63 6f 6d 22 } //01 00  = "pozxmcjsnqweasjasda.com"
		$a_00_2 = {3d 20 22 6f 68 71 6e 6a 77 65 6e 7a 68 6a 63 6e 71 77 65 72 61 2e 63 6f 6d 22 } //01 00  = "ohqnjwenzhjcnqwera.com"
		$a_00_3 = {52 65 70 6c 61 63 65 28 79 6f 7a 66 77 6a 6e 63 77 6b 76 75 6f 2c 20 22 36 35 34 37 34 37 36 35 34 37 32 32 39 31 31 32 33 38 22 2c 20 22 70 22 29 } //01 00  Replace(yozfwjncwkvuo, "654747654722911238", "p")
		$a_00_4 = {53 68 65 6c 6c 20 79 6f 7a 66 77 6a 6e 63 77 6b 76 75 6f } //01 00  Shell yozfwjncwkvuo
		$a_00_5 = {3d 20 52 65 70 6c 61 63 65 28 79 6f 7a 66 77 6a 6e 63 77 6b 76 75 6f 2c 20 22 43 55 52 52 45 4e 54 5f 44 47 41 5f 44 4f 4d 41 49 4e 22 2c 20 6a 6b 6a 75 7a 69 78 66 71 6b 75 64 67 29 } //01 00  = Replace(yozfwjncwkvuo, "CURRENT_DGA_DOMAIN", jkjuzixfqkudg)
		$a_00_6 = {22 71 77 65 74 79 75 74 6f 70 77 65 65 72 74 79 69 69 69 77 65 72 74 79 64 22 } //00 00  "qwetyutopweertyiiiwertyd"
	condition:
		any of ($a_*)
 
}