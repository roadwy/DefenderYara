
rule TrojanDownloader_Win32_Adload_CF{
	meta:
		description = "TrojanDownloader:Win32/Adload.CF,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {4c 69 6e 75 78 53 74 61 74 2e 67 61 6d 65 64 69 61 2e 63 6e } //1 LinuxStat.gamedia.cn
		$a_01_1 = {73 74 61 72 74 75 70 2e 65 78 65 } //1 startup.exe
		$a_01_2 = {5c 4a 69 6e 5a 51 5c 48 6f 6f 6b } //1 \JinZQ\Hook
		$a_01_3 = {2f 72 75 6e 2e 68 79 67 61 6d 65 38 38 38 38 2e 63 6e 2f } //1 /run.hygame8888.cn/
		$a_01_4 = {2f 76 69 64 65 6f 2e 75 72 6c 73 65 72 76 69 63 65 2e 63 6e 2f } //1 /video.urlservice.cn/
		$a_03_5 = {2f 65 64 6f 6e 6b 65 79 73 65 72 76 65 72 ?? 2e 38 38 30 30 2e 6f 72 67 2f } //1
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=5
 
}