
rule TrojanDownloader_Win32_Adload_CD{
	meta:
		description = "TrojanDownloader:Win32/Adload.CD,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_00_0 = {4c 69 6e 75 78 53 74 61 74 2e 67 61 6d 65 64 69 61 2e 63 6e 2f 53 74 61 72 74 } //3 LinuxStat.gamedia.cn/Start
		$a_01_1 = {5c 4e 65 77 47 61 6d 65 55 70 64 61 74 65 5c 47 61 6d 65 56 65 72 73 69 6f 6e 55 70 64 61 74 65 2e 74 65 6d 70 } //3 \NewGameUpdate\GameVersionUpdate.temp
		$a_02_2 = {2f 43 38 43 5f 49 4e 49 2f 47 61 6d 65 56 65 72 73 69 6f 6e 55 70 64 61 74 65 [0-01] 2e 74 78 74 } //3
		$a_01_3 = {2f 72 75 6e 2e 68 79 67 61 6d 65 38 38 38 38 2e 63 6e 2f } //1 /run.hygame8888.cn/
		$a_01_4 = {2f 76 69 64 65 6f 2e 75 72 6c 73 65 72 76 69 63 65 2e 63 6e 2f } //1 /video.urlservice.cn/
		$a_03_5 = {2f 65 64 6f 6e 6b 65 79 73 65 72 76 65 72 ?? 2e 38 38 30 30 2e 6f 72 67 2f } //1
	condition:
		((#a_00_0  & 1)*3+(#a_01_1  & 1)*3+(#a_02_2  & 1)*3+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=10
 
}