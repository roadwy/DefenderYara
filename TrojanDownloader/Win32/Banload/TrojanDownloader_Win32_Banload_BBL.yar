
rule TrojanDownloader_Win32_Banload_BBL{
	meta:
		description = "TrojanDownloader:Win32/Banload.BBL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 4f 46 54 57 41 52 45 5c 4d 49 43 52 4f 53 4f 46 54 5c 57 49 4e 44 4f 57 53 5c 43 55 52 52 45 4e 54 56 45 52 53 49 4f 4e 5c 52 55 4e } //1 SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\RUN
		$a_03_1 = {6d 61 71 75 69 6e 61 [0-10] 70 6c 75 67 69 6e } //1
		$a_03_2 = {ff 8d 55 f4 b8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 45 f4 e8 ?? ?? ?? ?? 8b d0 8d 45 f8 e8 ?? ?? ?? ?? 8b 45 f8 8d 55 fc e8 ?? ?? ?? ?? 8b 55 fc 90 04 01 02 8b b8 [0-04] b9 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 55 f0 b8 } //1
		$a_03_3 = {0f b6 44 30 ff 33 c3 89 45 ?? 3b 7d ?? 7c 0f 8b 45 ?? 05 ff 00 00 00 2b c7 89 45 ?? eb 03 29 7d ?? 8d 45 ?? 8b 55 ?? e8 ?? ?? ?? ?? 8b 55 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}