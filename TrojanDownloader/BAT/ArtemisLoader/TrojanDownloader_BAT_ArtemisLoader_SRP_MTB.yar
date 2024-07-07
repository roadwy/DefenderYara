
rule TrojanDownloader_BAT_ArtemisLoader_SRP_MTB{
	meta:
		description = "TrojanDownloader:BAT/ArtemisLoader.SRP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_03_0 = {09 08 11 05 8f 85 00 00 01 72 f4 04 00 70 28 90 01 03 0a 6f 90 01 03 0a 26 11 05 17 d6 13 05 11 05 11 04 31 db 90 00 } //5
		$a_01_1 = {50 6c 61 63 65 5f 53 65 61 72 63 68 2e 70 64 62 } //2 Place_Search.pdb
		$a_01_2 = {6f 00 6e 00 6c 00 79 00 6f 00 6e 00 65 00 5f 00 75 00 70 00 64 00 61 00 74 00 65 00 72 00 2e 00 65 00 78 00 65 00 } //2 onlyone_updater.exe
		$a_01_3 = {75 00 70 00 61 00 64 00 74 00 65 00 2e 00 64 00 6c 00 6c 00 } //1 upadte.dll
		$a_01_4 = {50 00 6c 00 61 00 63 00 65 00 5f 00 53 00 65 00 61 00 72 00 63 00 68 00 2e 00 65 00 78 00 65 00 } //1 Place_Search.exe
	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=11
 
}