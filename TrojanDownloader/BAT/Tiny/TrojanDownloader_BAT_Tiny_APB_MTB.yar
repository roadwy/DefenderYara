
rule TrojanDownloader_BAT_Tiny_APB_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.APB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,22 00 1d 00 08 00 00 05 00 "
		
	strings :
		$a_80_0 = {2f 43 20 63 68 6f 69 63 65 20 2f 43 20 59 20 2f 4e 20 2f 44 20 59 20 2f 54 20 33 20 26 20 44 65 6c } ///C choice /C Y /N /D Y /T 3 & Del  05 00 
		$a_80_1 = {66 69 6e 61 6c 72 65 73 2e 76 62 73 } //finalres.vbs  04 00 
		$a_80_2 = {52 65 6d 6f 76 65 45 58 45 } //RemoveEXE  04 00 
		$a_80_3 = {54 4f 4b 45 4e 5f 53 54 45 41 4c 45 52 5f 43 52 45 41 54 4f 52 } //TOKEN_STEALER_CREATOR  04 00 
		$a_80_4 = {47 65 74 54 65 6d 70 50 61 74 68 } //GetTempPath  04 00 
		$a_80_5 = {57 65 62 43 6c 69 65 6e 74 } //WebClient  04 00 
		$a_80_6 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //DownloadFile  04 00 
		$a_80_7 = {64 69 73 63 6f 72 64 } //discord  00 00 
	condition:
		any of ($a_*)
 
}