
rule TrojanDownloader_Win32_Unruy_A{
	meta:
		description = "TrojanDownloader:Win32/Unruy.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {80 7d 00 58 75 6a 80 7d ff 50 75 64 80 7d fe 55 75 5e a1 } //2
		$a_03_1 = {59 85 c0 74 3d 68 ?? ?? 40 00 50 e8 ?? ?? 00 00 ff 35 } //2
		$a_03_2 = {80 38 3d 75 03 c6 00 00 ff 45 ?? 8d 45 ?? 50 ff d6 39 45 ?? 72 e3 68 ?? ?? ?? ?? 8d 45 ?? 50 c6 85 } //4
	condition:
		((#a_01_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*4) >=4
 
}