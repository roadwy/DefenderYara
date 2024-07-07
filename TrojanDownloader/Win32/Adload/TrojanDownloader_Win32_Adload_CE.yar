
rule TrojanDownloader_Win32_Adload_CE{
	meta:
		description = "TrojanDownloader:Win32/Adload.CE,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 06 00 00 "
		
	strings :
		$a_00_0 = {4c 69 6e 75 78 53 74 61 74 2e 67 61 6d 65 64 69 61 2e 63 6e } //3 LinuxStat.gamedia.cn
		$a_01_1 = {5c 47 61 6d 65 56 65 72 73 69 6f 6e 55 70 64 61 74 65 5c 47 61 6d 65 56 65 72 73 69 6f 6e 55 70 64 61 74 65 2e 74 65 6d 70 } //3 \GameVersionUpdate\GameVersionUpdate.temp
		$a_02_2 = {2f 43 38 43 5f 49 4e 49 2f 47 61 6d 65 56 65 72 73 69 6f 6e 55 70 64 61 74 65 90 02 01 2e 74 78 74 90 00 } //3
		$a_01_3 = {2e 63 61 38 2e 63 6f 6d 2e 63 6e 2f } //1 .ca8.com.cn/
		$a_01_4 = {68 65 69 79 69 6e 67 31 39 37 36 2e 63 6f 6d 2f } //1 heiying1976.com/
		$a_03_5 = {2f 65 64 6f 6e 6b 65 79 73 65 72 76 65 72 90 01 01 2e 38 38 30 30 2e 6f 72 67 2f 90 00 } //1
	condition:
		((#a_00_0  & 1)*3+(#a_01_1  & 1)*3+(#a_02_2  & 1)*3+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1) >=10
 
}