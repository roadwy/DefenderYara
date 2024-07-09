
rule TrojanDownloader_Win32_Agent_QP{
	meta:
		description = "TrojanDownloader:Win32/Agent.QP,SIGNATURE_TYPE_PEHSTR_EXT,07 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {49 6e 74 65 72 6e 65 74 20 45 78 70 6c 6f 72 65 72 5c 49 45 58 50 4c 4f 52 45 2e 45 58 45 22 20 68 74 74 70 3a 2f 2f 77 77 77 2e 31 37 38 67 67 2e 63 6f 6d 2f 6c 69 61 6e 6a 69 65 2f } //2 Internet Explorer\IEXPLORE.EXE" http://www.178gg.com/lianjie/
		$a_03_1 = {49 6e 74 6f 72 6e 6f 74 [0-08] 45 78 70 6c 6f 72 6f 72 [0-08] 2e 6c 6e 6b } //2
		$a_00_2 = {5c 66 72 65 73 68 2e 65 78 65 } //1 \fresh.exe
		$a_00_3 = {74 61 6f 75 72 6c 2e 63 6f 6d } //1 taourl.com
		$a_00_4 = {64 6f 77 6e 6c 6f 61 64 5f 71 75 69 65 74 } //1 download_quiet
		$a_03_5 = {70 69 70 69 5f 64 61 65 5f [0-04] 2e 65 78 65 } //1
	condition:
		((#a_00_0  & 1)*2+(#a_03_1  & 1)*2+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}