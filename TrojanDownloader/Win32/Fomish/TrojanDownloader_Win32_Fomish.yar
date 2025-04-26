
rule TrojanDownloader_Win32_Fomish{
	meta:
		description = "TrojanDownloader:Win32/Fomish,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 0b 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f 59 79 6c 2e 6d 6f 66 69 73 68 2e 63 6e 2f 77 65 76 6f 6f 2f 64 61 74 61 2f 64 61 74 61 ?? 2e 64 61 74 } //1
		$a_01_1 = {68 74 74 70 3a 2f 2f 59 79 6c 2e 6d 6f 66 69 73 68 2e 63 6e 2f 77 65 76 6f 6f 2f 64 61 74 61 2e 64 61 74 } //1 http://Yyl.mofish.cn/wevoo/data.dat
		$a_01_2 = {68 74 74 70 3a 2f 2f 59 79 6c 2e 6d 6f 66 69 73 68 2e 63 6e 2f 69 6e 74 65 72 46 61 63 65 2f 41 63 74 69 76 65 53 65 65 64 2e 61 73 70 78 } //1 http://Yyl.mofish.cn/interFace/ActiveSeed.aspx
		$a_01_3 = {68 74 74 70 3a 2f 2f 59 79 6c 2e 6d 6f 66 69 73 68 2e 63 6e 2f 69 6e 74 65 72 66 61 63 65 2f 53 65 65 64 49 6e 73 74 61 6c 6c 2e 61 73 70 78 } //1 http://Yyl.mofish.cn/interface/SeedInstall.aspx
		$a_03_4 = {68 74 74 70 3a 2f 2f 59 79 6c 2e 6d 6f 66 69 73 68 2e 63 6e 2f 77 65 76 6f 6f 2f 6c 69 73 74 73 2f 32 30 30 ?? ?? ?? ?? ?? 2f 6c 69 73 74 2e 74 78 74 } //1
		$a_03_5 = {68 74 74 70 3a 2f 2f ?? ?? ?? 2e 6e 63 61 73 74 2e 63 6e 2f 6c 69 73 74 73 2f 32 30 30 ?? ?? ?? ?? ?? 2f 6c 69 73 74 2e 74 78 74 } //1
		$a_01_6 = {68 74 74 70 3a 2f 2f 72 65 70 2e 65 79 65 65 7a 2e 63 6f 6d 2f 47 65 74 41 72 65 61 2e 61 73 70 78 } //1 http://rep.eyeez.com/GetArea.aspx
		$a_01_7 = {54 68 69 72 64 53 6f 66 74 3d 25 73 26 49 44 3d 25 73 26 53 74 61 74 65 3d 31 26 4d 61 63 3d 25 73 26 49 6e 73 74 61 6c 6c 54 69 6d 65 3d 25 73 } //1 ThirdSoft=%s&ID=%s&State=1&Mac=%s&InstallTime=%s
		$a_01_8 = {54 68 69 72 64 53 6f 66 74 3d 25 73 26 53 74 61 74 65 3d 31 26 4d 61 63 3d 25 73 } //1 ThirdSoft=%s&State=1&Mac=%s
		$a_01_9 = {45 58 45 5f 44 4c 31 } //1 EXE_DL1
		$a_01_10 = {45 58 45 5f 44 4c 32 } //1 EXE_DL2
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1+(#a_01_9  & 1)*1+(#a_01_10  & 1)*1) >=10
 
}