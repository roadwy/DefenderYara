
rule TrojanDownloader_Win32_Tandfuy_C{
	meta:
		description = "TrojanDownloader:Win32/Tandfuy.C,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {8b 44 24 04 80 38 00 b1 fe 74 0f eb 03 8d 49 00 30 08 40 fe c9 80 38 00 75 f6 c3 } //1
		$a_01_1 = {66 63 73 74 2e 63 6f 2e 6b 72 2f 62 6f 61 72 64 2f 64 61 74 61 2f 69 6e 73 69 64 65 74 6f 6f 6c 73 31 2e 70 68 70 00 } //1
		$a_01_2 = {74 74 74 2e 64 61 74 00 } //1
		$a_01_3 = {2b c2 4f 8a 4f 01 47 84 c9 75 f8 8b c8 c1 e9 02 8b f2 f3 a5 8b c8 8d 54 24 08 83 e1 03 52 f3 a4 ff 15 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}