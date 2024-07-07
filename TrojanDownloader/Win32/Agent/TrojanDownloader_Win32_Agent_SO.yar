
rule TrojanDownloader_Win32_Agent_SO{
	meta:
		description = "TrojanDownloader:Win32/Agent.SO,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_03_0 = {5c 6c 6f 61 64 64 6b 2e 69 6e 66 90 09 08 00 90 03 02 02 44 6b 4d 79 54 65 6d 70 90 00 } //10
		$a_01_1 = {5c 72 75 6e 33 32 25 64 2e 65 78 65 } //1 \run32%d.exe
		$a_01_2 = {5c 6e 6f 74 65 36 34 2e 65 78 65 } //1 \note64.exe
		$a_01_3 = {5c 6e 6f 74 65 70 61 64 33 32 2e 65 78 65 } //1 \notepad32.exe
		$a_01_4 = {25 73 5c 6e 6f 74 65 70 61 64 25 64 2e 65 78 65 } //1 %s\notepad%d.exe
	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=11
 
}