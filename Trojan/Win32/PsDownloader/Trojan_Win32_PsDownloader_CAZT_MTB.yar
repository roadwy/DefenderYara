
rule Trojan_Win32_PsDownloader_CAZT_MTB{
	meta:
		description = "Trojan:Win32/PsDownloader.CAZT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 74 74 70 3a 2f 2f 73 6c 61 73 68 65 72 2e 64 64 6e 73 2e 6e 65 74 2f 64 6f 77 6e 6c 6f 61 64 2f 70 6f 77 65 72 73 68 65 6c 6c 2f 4f 6d 31 68 64 48 52 70 5a 6d 56 7a 64 47 46 30 61 57 39 75 49 47 56 30 64 77 3d 3d } //1 http://slasher.ddns.net/download/powershell/Om1hdHRpZmVzdGF0aW9uIGV0dw==
		$a_01_1 = {4c 6f 61 64 57 69 74 68 50 61 72 74 69 61 6c 4e 61 6d 65 } //1 LoadWithPartialName
		$a_01_2 = {47 61 6d 65 20 69 73 20 6e 6f 77 20 72 65 61 64 79 20 74 6f 20 70 6c 61 79 } //1 Game is now ready to play
		$a_01_3 = {73 74 61 72 74 20 2f 62 20 70 6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 6e 6f 6c 20 2d 77 20 31 20 2d 6e 6f 70 20 2d 65 70 20 62 79 70 61 73 73 } //1 start /b powershell.exe -nol -w 1 -nop -ep bypass
		$a_01_4 = {62 00 32 00 65 00 69 00 6e 00 63 00 66 00 69 00 6c 00 65 00 } //1 b2eincfile
		$a_01_5 = {6c 00 61 00 75 00 6e 00 63 00 68 00 65 00 72 00 2e 00 62 00 61 00 74 00 } //1 launcher.bat
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}