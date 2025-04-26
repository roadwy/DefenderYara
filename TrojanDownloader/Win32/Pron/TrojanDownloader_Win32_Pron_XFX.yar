
rule TrojanDownloader_Win32_Pron_XFX{
	meta:
		description = "TrojanDownloader:Win32/Pron.XFX,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2a 00 5c 00 41 00 43 00 3a 00 5c 00 44 00 6f 00 63 00 75 00 6d 00 65 00 6e 00 74 00 73 00 20 00 61 00 6e 00 64 00 20 00 53 00 65 00 74 00 74 00 69 00 6e 00 67 00 73 00 5c 00 41 00 6c 00 6c 00 20 00 55 00 73 00 65 00 72 00 73 00 5c 00 67 00 68 00 69 00 6a 00 6b 00 5c 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 31 00 2e 00 76 00 62 00 70 00 } //1 *\AC:\Documents and Settings\All Users\ghijk\Project1.vbp
		$a_01_1 = {50 00 61 00 79 00 54 00 69 00 6d 00 65 00 20 00 3a 00 } //1 PayTime :
		$a_01_2 = {57 00 53 00 63 00 72 00 69 00 70 00 74 00 2e 00 53 00 68 00 65 00 6c 00 6c 00 } //1 WScript.Shell
		$a_01_3 = {61 00 64 00 75 00 6c 00 74 00 2d 00 64 00 6f 00 75 00 67 00 61 00 67 00 61 00 2e 00 65 00 78 00 65 00 } //1 adult-dougaga.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}