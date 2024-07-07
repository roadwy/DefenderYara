
rule TrojanDownloader_Win32_Dalbot_A{
	meta:
		description = "TrojanDownloader:Win32/Dalbot.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {64 6f 77 6e 6c 6f 61 64 63 6f 70 79 3a 00 00 00 64 6f 77 6e 6c 6f 61 64 3a 00 00 00 67 65 74 75 72 6c 3a } //2
		$a_01_1 = {2f 6c 6f 67 6f 2e 68 74 6d 6c } //1 /logo.html
		$a_01_2 = {2f 6c 6f 67 6f 2e 68 74 6d 6c 45 45 45 45 45 45 45 45 45 45 45 45 45 45 45 45 45 45 45 45 45 45 73 6c 65 65 70 3a } //1 /logo.htmlEEEEEEEEEEEEEEEEEEEEEEsleep:
		$a_03_3 = {8a 0f 80 f1 90 01 01 46 88 08 8b 44 24 1c 3b c6 77 ac 6a 01 90 00 } //3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*3) >=4
 
}