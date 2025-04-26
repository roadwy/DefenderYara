
rule TrojanDownloader_Win32_Futitu_A{
	meta:
		description = "TrojanDownloader:Win32/Futitu.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {2f 63 6f 75 6e 74 2e 61 73 70 3f 61 63 74 3d 69 6e 73 74 61 6c 6c 26 65 78 65 63 3d 00 } //1
		$a_00_1 = {2f 63 6f 75 6e 74 5f 6c 69 76 65 2e 61 73 70 3f 65 78 65 63 3d 58 54 75 6e 65 2e 65 78 65 00 } //1
		$a_00_2 = {5c 58 54 75 6e 65 5c 58 54 75 6e 65 2e 65 78 65 00 } //1
		$a_03_3 = {8d 44 24 10 6a 00 50 ff 15 ?? ?? ?? ?? 85 c0 74 0a e8 ?? ?? ?? ?? a2 ?? ?? ?? ?? 68 88 13 00 00 ff d7 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}