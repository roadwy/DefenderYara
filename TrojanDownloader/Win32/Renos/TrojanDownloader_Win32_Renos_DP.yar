
rule TrojanDownloader_Win32_Renos_DP{
	meta:
		description = "TrojanDownloader:Win32/Renos.DP,SIGNATURE_TYPE_PEHSTR_EXT,27 00 1a 00 0f 00 00 "
		
	strings :
		$a_01_0 = {72 65 67 41 52 33 2e 72 65 67 00 } //1
		$a_01_1 = {72 65 67 41 58 33 2e 62 61 74 00 } //1
		$a_01_2 = {73 65 6c 66 64 65 6c 33 2e 62 61 74 00 } //1
		$a_01_3 = {4d 69 6e 75 74 65 73 54 6f 55 6e 69 6e 73 74 61 6c 6c } //2 MinutesToUninstall
		$a_01_4 = {53 6c 65 65 70 53 65 63 6f 6e 64 73 } //2 SleepSeconds
		$a_01_5 = {4f 70 65 6e 49 45 4d 69 6e 75 74 65 73 00 } //2 灏湥䕉楍畮整s
		$a_01_6 = {42 61 6c 6c 6f 6f 6e 54 69 74 6c 65 00 } //2
		$a_01_7 = {53 68 6f 77 42 61 6c 6c 6f 6f 6e 4d 69 6e 75 74 65 73 00 } //2
		$a_01_8 = {55 52 4c 5f 49 45 } //2 URL_IE
		$a_01_9 = {55 52 4c 5f 42 61 6c 6c 6f 6f 6e } //2 URL_Balloon
		$a_01_10 = {42 61 6c 6c 6f 6f 6e 54 65 78 74 } //2 BalloonText
		$a_00_11 = {25 00 64 00 6f 00 6d 00 65 00 6e 00 25 00 } //5 %domen%
		$a_00_12 = {25 00 61 00 66 00 66 00 69 00 64 00 25 00 } //5 %affid%
		$a_00_13 = {25 00 77 00 6f 00 72 00 6b 00 6d 00 69 00 6e 00 25 00 } //5 %workmin%
		$a_01_14 = {30 39 45 32 33 46 32 43 2d 45 44 31 45 2d 34 33 46 43 2d 39 41 41 31 2d 31 33 33 32 31 36 32 41 33 35 41 45 } //5 09E23F2C-ED1E-43FC-9AA1-1332162A35AE
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*2+(#a_01_5  & 1)*2+(#a_01_6  & 1)*2+(#a_01_7  & 1)*2+(#a_01_8  & 1)*2+(#a_01_9  & 1)*2+(#a_01_10  & 1)*2+(#a_00_11  & 1)*5+(#a_00_12  & 1)*5+(#a_00_13  & 1)*5+(#a_01_14  & 1)*5) >=26
 
}