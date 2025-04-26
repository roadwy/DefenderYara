
rule TrojanDownloader_Win32_Wintrim_BZ{
	meta:
		description = "TrojanDownloader:Win32/Wintrim.BZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {01 3a 0f 85 ?? ?? 00 00 80 ?? 02 5c 0f 85 ?? ?? 00 00 80 ?? 03 6d 0f 85 ?? ?? 00 00 80 ?? 04 79 0f 85 ?? ?? 00 00 80 ?? 05 61 0f 85 } //1
		$a_03_1 = {df e0 f6 c4 40 75 ?? d9 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}