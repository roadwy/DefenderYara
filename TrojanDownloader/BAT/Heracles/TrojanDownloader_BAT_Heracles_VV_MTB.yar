
rule TrojanDownloader_BAT_Heracles_VV_MTB{
	meta:
		description = "TrojanDownloader:BAT/Heracles.VV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 72 15 00 00 70 6f 18 00 00 0a 0a dd 0d 00 00 00 } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}
rule TrojanDownloader_BAT_Heracles_VV_MTB_2{
	meta:
		description = "TrojanDownloader:BAT/Heracles.VV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {09 06 08 91 58 07 08 91 58 20 00 01 00 00 5d 0d 06 08 91 13 12 06 08 06 09 91 9c 06 09 11 12 9c 08 17 58 0c 08 20 00 01 00 00 32 d4 } //2
		$a_81_1 = {24 33 37 35 63 35 65 66 66 2d 30 36 35 30 2d 34 33 30 31 2d 38 35 65 66 2d 33 38 32 63 66 65 66 61 39 61 64 66 } //2 $375c5eff-0650-4301-85ef-382cfefa9adf
		$a_81_2 = {56 51 50 2e 65 78 65 } //2 VQP.exe
	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2+(#a_81_2  & 1)*2) >=6
 
}