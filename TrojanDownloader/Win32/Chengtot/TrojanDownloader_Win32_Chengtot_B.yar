
rule TrojanDownloader_Win32_Chengtot_B{
	meta:
		description = "TrojanDownloader:Win32/Chengtot.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {68 00 00 00 [0-12] 74 00 [0-12] 70 00 [0-12] 3a 00 [0-12] 2f 00 [0-12] 77 00 [0-12] 6f 00 [0-12] 6c 00 [0-12] 63 00 [0-12] 6d 00 [0-12] 61 00 [0-12] 3f 00 [0-12] 71 00 [0-12] 3d 00 [0-20] 73 65 78 20 64 6f 77 6e 6c 6f 61 64 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule TrojanDownloader_Win32_Chengtot_B_2{
	meta:
		description = "TrojanDownloader:Win32/Chengtot.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {83 3e 0a 7e 05 83 3f 00 75 ?? e8 ?? b3 ff ff c7 06 01 00 00 00 83 3e 02 0f 85 ?? 03 00 00 c7 06 db 04 00 00 eb 1e 8b 07 50 } //1
		$a_03_1 = {6a 00 6a 00 6a 01 68 ?? ?? ?? ?? ff 33 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 33 68 ?? ?? ?? ?? ff 33 68 ?? ?? ?? ?? ff 33 68 ?? ?? ?? ?? ff 33 68 ?? ?? ?? ?? ff 33 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? 68 ?? ?? ?? ?? 8d 45 fc ba 12 00 00 00 } //1
		$a_01_2 = {5b 59 59 5d c3 00 ff ff ff ff 04 00 00 00 68 74 74 70 00 00 00 00 ff ff ff ff 03 00 00 00 3a 2f 2f 00 ff ff ff ff 01 00 00 00 2f 00 00 00 ff ff ff ff 02 00 00 00 64 72 00 00 ff ff ff ff 01 00 00 00 76 00 00 00 ff ff ff ff 02 00 00 00 33 32 00 00 ff ff ff ff 01 00 00 00 2e 00 00 00 ff ff ff ff 04 00 00 00 64 61 74 61 00 00 00 00 ff ff } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}