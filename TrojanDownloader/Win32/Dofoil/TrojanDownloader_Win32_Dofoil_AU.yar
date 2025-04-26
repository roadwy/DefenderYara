
rule TrojanDownloader_Win32_Dofoil_AU{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.AU,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {e8 e7 df 00 00 83 c4 04 68 1a 04 00 00 ff d7 6a 00 e8 e9 dc 00 00 } //1
		$a_01_1 = {6a 00 68 df e2 f0 01 e8 4e fb ff ff } //1
		$a_01_2 = {48 00 65 00 6c 00 6c 00 53 00 74 00 61 00 72 00 2e 00 65 00 78 00 65 00 } //1 HellStar.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_Win32_Dofoil_AU_2{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.AU,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 7a 00 7a 00 7a 00 69 00 70 00 2e 00 74 00 69 00 6e 00 79 00 2e 00 75 00 73 00 2f 00 6d 00 61 00 78 00 30 00 32 00 31 00 35 00 34 00 61 00 } //1 https://zzzip.tiny.us/max02154a
		$a_01_1 = {43 00 6b 00 70 00 67 00 61 00 75 00 69 00 64 00 71 00 7a 00 6b 00 68 00 70 00 69 00 6e 00 79 00 65 00 70 00 } //1 Ckpgauidqzkhpinyep
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule TrojanDownloader_Win32_Dofoil_AU_3{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.AU,SIGNATURE_TYPE_PEHSTR,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {52 00 6f 00 75 00 74 00 65 00 73 00 20 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 61 00 74 00 69 00 6f 00 6e 00 } //2 Routes Installation
		$a_01_1 = {73 00 65 00 61 00 72 00 63 00 68 00 5f 00 68 00 79 00 70 00 65 00 72 00 66 00 73 00 5f 00 32 00 31 00 33 00 } //2 search_hyperfs_213
		$a_01_2 = {79 00 61 00 6e 00 77 00 61 00 6e 00 67 00 } //2 yanwang
		$a_01_3 = {66 00 69 00 78 00 74 00 6f 00 6f 00 6c 00 2e 00 65 00 78 00 65 00 } //1 fixtool.exe
		$a_01_4 = {53 00 62 00 69 00 65 00 44 00 6c 00 6c 00 2e 00 64 00 6c 00 6c 00 } //1 SbieDll.dll
		$a_01_5 = {56 00 69 00 72 00 74 00 75 00 61 00 6c 00 42 00 6f 00 78 00 } //1 VirtualBox
		$a_01_6 = {62 00 65 00 61 00 72 00 76 00 70 00 6e 00 33 00 } //1 bearvpn3
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}
rule TrojanDownloader_Win32_Dofoil_AU_4{
	meta:
		description = "TrojanDownloader:Win32/Dofoil.AU,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 69 00 70 00 6c 00 6f 00 67 00 67 00 65 00 72 00 2e 00 6f 00 72 00 67 00 2f 00 31 00 55 00 73 00 68 00 70 00 37 00 } //1 https://iplogger.org/1Ushp7
		$a_01_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 69 00 70 00 6c 00 6f 00 67 00 67 00 65 00 72 00 2e 00 6f 00 72 00 67 00 2f 00 31 00 6e 00 47 00 55 00 69 00 37 00 } //1 https://iplogger.org/1nGUi7
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 39 00 35 00 2e 00 31 00 36 00 31 00 2e 00 36 00 38 00 2e 00 35 00 38 00 2f 00 31 00 2e 00 65 00 78 00 65 00 } //1 http://195.161.68.58/1.exe
		$a_01_3 = {47 00 61 00 6d 00 65 00 73 00 20 00 6f 00 66 00 20 00 74 00 68 00 65 00 20 00 63 00 68 00 72 00 6f 00 6d 00 65 00 } //1 Games of the chrome
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}