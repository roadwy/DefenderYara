
rule TrojanDownloader_Win32_Zlob_AMM{
	meta:
		description = "TrojanDownloader:Win32/Zlob.AMM,SIGNATURE_TYPE_PEHSTR,0b 00 0a 00 0b 00 00 "
		
	strings :
		$a_01_0 = {49 74 20 6d 61 79 20 62 65 20 70 6f 73 73 69 62 6c 65 20 74 6f 20 73 6b 69 70 20 74 68 69 73 20 63 68 65 63 6b 20 75 73 69 6e 67 20 74 68 65 20 2f 4e 43 52 43 20 63 6f 6d 6d 61 6e 64 20 6c 69 6e 65 20 73 77 69 74 63 68 } //1 It may be possible to skip this check using the /NCRC command line switch
		$a_01_1 = {64 65 6c 20 2f 46 20 2f 51 20 69 6d 65 78 2e 62 61 74 } //1 del /F /Q imex.bat
		$a_01_2 = {64 6f 77 6e 6c 6f 61 64 5f 71 75 69 65 74 } //1 download_quiet
		$a_01_3 = {50 72 6f 78 79 2d 41 75 74 68 6f 72 69 7a 61 74 69 6f 6e 3a } //1 Proxy-Authorization:
		$a_01_4 = {55 73 65 72 2d 41 67 65 6e 74 3a } //1 User-Agent:
		$a_01_5 = {43 6f 6e 6e 65 63 74 69 6e 67 20 2e 2e 2e } //1 Connecting ...
		$a_01_6 = {4e 4f 54 49 43 45 20 54 4f 20 55 53 45 52 3a 20 54 48 49 53 20 45 4e 44 20 55 53 45 52 20 4c 49 43 45 4e 53 45 20 41 47 52 45 45 4d 45 4e 54 } //1 NOTICE TO USER: THIS END USER LICENSE AGREEMENT
		$a_01_7 = {53 70 65 63 69 61 6c 20 4e 6f 74 69 63 65 20 66 6f 72 20 4e 6f 6e 2d 45 6e 67 6c 69 73 68 20 53 70 65 61 6b 65 72 73 3a } //1 Special Notice for Non-English Speakers:
		$a_01_8 = {56 69 64 65 6f 20 43 6f 64 65 63 20 53 6f 66 74 77 61 72 65 20 69 73 20 73 75 69 74 65 64 20 70 72 69 6d 61 72 69 6c 79 20 66 6f 72 20 74 68 65 20 75 73 65 20 6f 66 20 45 6e 67 6c 69 73 68 } //1 Video Codec Software is suited primarily for the use of English
		$a_01_9 = {23 33 32 37 37 30 } //1 #32770
		$a_01_10 = {4e 75 6c 6c 73 6f 66 74 20 49 6e 73 74 61 6c 6c 20 53 79 73 74 65 6d } //1 Nullsoft Install System
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=10
 
}