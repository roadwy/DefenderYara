
rule TrojanDownloader_WinNT_OpenStream_BL{
	meta:
		description = "TrojanDownloader:WinNT/OpenStream.BL,SIGNATURE_TYPE_JAVAHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_02_0 = {01 00 20 61 62 63 64 65 66 67 68 69 6a 6b 6c 6d 6e 6f ?? 71 72 73 74 75 76 77 78 79 7a 3a 2f 2e 3d 26 2d } //10
		$a_00_1 = {06 5b 5e 30 2d 39 5d } //10
		$a_03_2 = {01 00 10 30 ?? 31 35 ?? ?? ?? ?? ?? ?? ?? ?? 31 39 ?? 30 } //1
		$a_03_3 = {01 00 12 34 ?? 32 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? 38 31 ?? 34 31 } //1
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=21
 
}