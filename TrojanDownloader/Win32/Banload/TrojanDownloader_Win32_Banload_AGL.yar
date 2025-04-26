
rule TrojanDownloader_Win32_Banload_AGL{
	meta:
		description = "TrojanDownloader:Win32/Banload.AGL,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {17 00 00 00 63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 5c 42 44 5c 00 ff ff ff ff 01 00 00 00 2e 00 00 00 ff ff ff ff 04 00 00 00 2e 65 78 65 00 00 00 00 ff ff ff ff 04 00 00 00 2e 74 78 74 } //1
		$a_01_1 = {05 00 00 00 63 68 61 76 65 00 00 00 ff ff ff ff 01 00 00 00 24 00 } //1
		$a_01_2 = {07 55 4c 6f 61 64 65 72 } //1 唇潌摡牥
		$a_01_3 = {8b b3 1c 03 00 00 8d 55 f8 8b 83 f8 02 00 00 e8 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}