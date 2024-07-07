
rule TrojanDownloader_O97M_Powdow_PV_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {61 73 64 2e 52 75 6e 20 28 5a 29 } //1 asd.Run (Z)
		$a_00_1 = {61 73 64 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 22 57 53 63 72 69 70 74 2e 53 68 65 6c 6c 22 29 } //1 asd = CreateObject("WScript.Shell")
		$a_00_2 = {5a 20 3d 20 22 70 6f 77 65 72 73 68 65 6c 6c 20 2d 6e 6f 50 20 2d 73 74 61 20 2d 77 20 31 20 2d 65 6e 63 } //1 Z = "powershell -noP -sta -w 1 -enc
		$a_00_3 = {55 77 42 46 41 48 51 41 4c 51 42 57 41 47 45 41 55 67 } //1 UwBFAHQALQBWAGEAUg
		$a_00_4 = {3d 20 5a 20 2b 20 22 41 6e 41 46 67 41 4a 77 41 73 41 43 63 41 53 51 42 46 41 43 63 41 4b 51 41 3d } //1 = Z + "AnAFgAJwAsACcASQBFACcAKQA=
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Powdow_PV_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.PV!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_00_0 = {3d 20 6a 6b 6a 75 7a 69 78 66 71 6b 75 64 67 20 26 20 22 2e 6e 65 74 22 } //1 = jkjuzixfqkudg & ".net"
		$a_00_1 = {3d 20 22 70 6f 7a 78 6d 63 6a 73 6e 71 77 65 61 73 6a 61 73 64 61 2e 63 6f 6d 22 } //1 = "pozxmcjsnqweasjasda.com"
		$a_00_2 = {3d 20 22 6f 68 71 6e 6a 77 65 6e 7a 68 6a 63 6e 71 77 65 72 61 2e 63 6f 6d 22 } //1 = "ohqnjwenzhjcnqwera.com"
		$a_00_3 = {52 65 70 6c 61 63 65 28 79 6f 7a 66 77 6a 6e 63 77 6b 76 75 6f 2c 20 22 36 35 34 37 34 37 36 35 34 37 32 32 39 31 31 32 33 38 22 2c 20 22 70 22 29 } //1 Replace(yozfwjncwkvuo, "654747654722911238", "p")
		$a_00_4 = {53 68 65 6c 6c 20 79 6f 7a 66 77 6a 6e 63 77 6b 76 75 6f } //1 Shell yozfwjncwkvuo
		$a_00_5 = {3d 20 52 65 70 6c 61 63 65 28 79 6f 7a 66 77 6a 6e 63 77 6b 76 75 6f 2c 20 22 43 55 52 52 45 4e 54 5f 44 47 41 5f 44 4f 4d 41 49 4e 22 2c 20 6a 6b 6a 75 7a 69 78 66 71 6b 75 64 67 29 } //1 = Replace(yozfwjncwkvuo, "CURRENT_DGA_DOMAIN", jkjuzixfqkudg)
		$a_00_6 = {22 71 77 65 74 79 75 74 6f 70 77 65 65 72 74 79 69 69 69 77 65 72 74 79 64 22 } //1 "qwetyutopweertyiiiwertyd"
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=7
 
}