
rule TrojanDownloader_Win32_Small_CAK{
	meta:
		description = "TrojanDownloader:Win32/Small.CAK,SIGNATURE_TYPE_PEHSTR,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {63 61 6f 67 61 6d 65 2e 33 33 32 32 2e 6f 72 67 } //1 caogame.3322.org
		$a_01_1 = {33 36 30 74 72 61 79 2e 65 78 65 } //1 360tray.exe
		$a_01_2 = {64 72 69 76 65 72 73 5c 66 61 6b 65 64 69 73 6b } //1 drivers\fakedisk
		$a_01_3 = {2f 63 20 70 69 6e 67 20 30 20 26 20 64 65 6c } //1 /c ping 0 & del
		$a_01_4 = {61 76 4e 75 6d 3d 25 64 } //1 avNum=%d
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}