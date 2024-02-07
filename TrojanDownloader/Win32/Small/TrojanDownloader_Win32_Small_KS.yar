
rule TrojanDownloader_Win32_Small_KS{
	meta:
		description = "TrojanDownloader:Win32/Small.KS,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {77 31 6e 74 30 75 63 68 31 6e 73 74 40 6c 6c 33 72 00 } //01 00  ㅷ瑮田档渱瑳汀㍬r
		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 77 69 6e 2d 74 6f 75 63 68 2e 63 6f 6d } //01 00  http://www.win-touch.com
		$a_01_2 = {25 73 25 73 2e 65 78 65 } //01 00  %s%s.exe
		$a_01_3 = {6d 75 74 65 78 57 54 52 65 63 } //01 00  mutexWTRec
		$a_01_4 = {73 61 63 63 2f 66 65 65 64 62 61 63 6b 2e 70 68 70 } //00 00  sacc/feedback.php
	condition:
		any of ($a_*)
 
}