
rule TrojanDownloader_BAT_Tiny_RK_MTB{
	meta:
		description = "TrojanDownloader:BAT/Tiny.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 20 00 2d 00 69 00 6e 00 70 00 75 00 74 00 66 00 6f 00 72 00 6d 00 61 00 74 00 20 00 6e 00 6f 00 6e 00 65 00 20 00 2d 00 6f 00 75 00 74 00 70 00 75 00 74 00 66 00 6f 00 72 00 6d 00 61 00 74 00 20 00 6e 00 6f 00 6e 00 65 00 20 00 2d 00 4e 00 6f 00 6e 00 49 00 6e 00 74 00 65 00 72 00 61 00 63 00 74 00 69 00 76 00 65 00 20 00 2d 00 43 00 6f 00 6d 00 6d 00 61 00 6e 00 64 00 20 00 41 00 64 00 64 00 2d 00 4d 00 70 00 50 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 20 00 2d 00 45 00 78 00 63 00 6c 00 75 00 73 00 69 00 6f 00 6e 00 45 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 20 00 22 00 65 00 78 00 65 00 22 00 } //1 powershell -inputformat none -outputformat none -NonInteractive -Command Add-MpPreference -ExclusionExtension "exe"
		$a_81_1 = {68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f 39 31 37 30 33 39 32 30 31 38 34 33 38 33 34 39 36 31 2f 39 31 37 30 33 39 32 35 39 36 37 30 37 30 30 30 34 32 2f 4c 6f 61 64 65 72 5f 4c 69 6e 6b 5f 43 68 61 6e 67 65 72 2e 65 78 65 } //1 https://cdn.discordapp.com/attachments/917039201843834961/917039259670700042/Loader_Link_Changer.exe
		$a_01_2 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_01_3 = {57 72 69 74 65 41 6c 6c 42 79 74 65 73 } //1 WriteAllBytes
	condition:
		((#a_01_0  & 1)*1+(#a_81_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}