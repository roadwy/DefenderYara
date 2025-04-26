
rule TrojanDownloader_Win32_Bloon_gen_A{
	meta:
		description = "TrojanDownloader:Win32/Bloon.gen!A,SIGNATURE_TYPE_PEHSTR,19 00 19 00 07 00 00 "
		
	strings :
		$a_01_0 = {59 6f 75 72 20 76 69 72 75 73 20 70 72 6f 74 65 63 74 69 6f 6e 20 73 74 61 74 75 73 20 69 73 20 62 61 64 } //10 Your virus protection status is bad
		$a_01_1 = {53 70 79 77 61 72 65 20 41 63 74 69 76 69 74 79 20 44 65 74 65 63 74 65 64 } //10 Spyware Activity Detected
		$a_01_2 = {5c 62 61 6c 6c 6f 6f 6e 2e 77 61 76 } //1 \balloon.wav
		$a_01_3 = {42 49 4e 41 52 59 } //1 BINARY
		$a_01_4 = {53 68 65 6c 6c 5f 54 72 61 79 57 6e 64 } //1 Shell_TrayWnd
		$a_01_5 = {54 72 61 79 4e 6f 74 69 66 79 57 6e 64 } //1 TrayNotifyWnd
		$a_01_6 = {73 70 79 77 61 72 65 } //1 spyware
	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=25
 
}