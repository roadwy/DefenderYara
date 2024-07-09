
rule TrojanDownloader_Win32_Kanav_B{
	meta:
		description = "TrojanDownloader:Win32/Kanav.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 40 59 33 c0 8d bd ?? ?? ff ff f3 ab 66 ab aa 8d 85 ?? ?? ff ff 50 68 ?? ?? ?? ?? e8 } //1
		$a_00_1 = {38 31 41 36 41 38 44 32 30 43 41 32 41 45 } //1 81A6A8D20CA2AE
		$a_00_2 = {2d 73 74 61 72 74 00 73 74 61 72 74 } //1 猭慴瑲猀慴瑲
		$a_00_3 = {5c 41 59 4c 61 75 6e 63 68 2e 65 78 65 } //1 \AYLaunch.exe
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}