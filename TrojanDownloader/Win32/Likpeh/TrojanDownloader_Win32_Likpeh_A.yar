
rule TrojanDownloader_Win32_Likpeh_A{
	meta:
		description = "TrojanDownloader:Win32/Likpeh.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {4b 49 4c 4c 8d 50 01 8a 08 40 3a cb 75 f9 2b c2 83 f8 03 76 20 8d 8c 24 ?? ?? 00 00 51 8d 94 24 ?? ?? 00 00 52 e8 ?? ?? ?? ?? 83 c4 08 85 c0 0f 85 ?? ?? ?? ?? 8d 84 24 ?? ?? 00 00 c7 84 24 ?? ?? 00 00 68 74 74 70 } //1
		$a_03_1 = {83 c4 14 51 e8 ?? ?? ?? ?? 83 c4 04 68 40 0d 03 00 e8 ?? ?? ?? ?? 83 c4 04 68 3f 0d 03 00 8b f0 6a 00 56 e8 ?? ?? ?? ?? 83 c4 0c } //1
		$a_00_2 = {2f 2f 25 73 25 73 3f 61 63 74 25 73 6f 72 26 76 3d 31 26 61 3d 25 64 26 69 64 3d 25 73 26 68 61 72 64 69 64 3d 25 73 } //1 //%s%s?act%sor&v=1&a=%d&id=%s&hardid=%s
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}