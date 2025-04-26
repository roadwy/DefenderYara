
rule TrojanDownloader_Win32_Clagger_H{
	meta:
		description = "TrojanDownloader:Win32/Clagger.H,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_03_0 = {7e 27 8b 4d ec 0f be c0 8b 49 f8 2b c8 51 50 8d 4d ec e8 ?? ?? 00 00 68 ?? ?? 40 00 68 ?? ?? 40 00 8d 4d ec e8 ?? ?? 00 00 8d ?? ec 8d 4d e8 ?? e8 ?? ?? 00 00 68 00 00 00 04 } //3
		$a_03_1 = {99 6a 17 68 ff e7 76 48 52 50 e8 ?? ?? 00 00 05 0f 27 00 00 } //3
		$a_00_2 = {70 68 70 00 65 78 65 00 3f } //1
		$a_00_3 = {64 65 6c 20 63 3a 5c 31 2e 62 61 74 } //1 del c:\1.bat
		$a_00_4 = {3a 2a 3a 45 6e 61 62 6c 65 64 3a 7a 78 } //1 :*:Enabled:zx
		$a_00_5 = {72 3d 25 64 } //1 r=%d
	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=8
 
}