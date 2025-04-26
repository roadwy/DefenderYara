
rule TrojanDownloader_Win32_Kilfno_C{
	meta:
		description = "TrojanDownloader:Win32/Kilfno.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {10 00 10 32 d1 88 ?? ?? 10 00 10 40 3d ?? ?? ?? ?? 7c ea } //2
		$a_01_1 = {64 a1 30 00 00 00 40 40 8b 00 25 ff 00 00 00 85 c0 75 02 eb 04 b0 01 eb 02 } //1
		$a_03_2 = {68 4b e1 22 00 50 ff 15 ?? ?? ?? ?? 85 c0 74 10 } //1
		$a_01_3 = {48 75 1c 72 03 73 01 e8 e8 } //1
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}