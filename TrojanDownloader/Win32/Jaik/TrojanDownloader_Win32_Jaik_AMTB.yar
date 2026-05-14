
rule TrojanDownloader_Win32_Jaik_AMTB{
	meta:
		description = "TrojanDownloader:Win32/Jaik!AMTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_01_0 = {83 7d e8 0f 8d 34 01 8d 4d d4 0f 47 ca 33 d2 f7 75 e4 8a 14 0a 32 16 8b 4f 10 8b 77 14 88 55 c4 3b ce 73 19 8d 41 01 89 47 10 8b c7 83 fe 0f 76 02 8b 07 } //5
		$a_80_1 = {76 6d 77 61 72 65 } //vmware  1
		$a_80_2 = {76 69 72 74 75 61 6c 62 6f 78 } //virtualbox  1
		$a_80_3 = {70 72 6f 63 6d 6f 6e } //procmon  1
		$a_80_4 = {77 69 72 65 73 68 61 72 6b } //wireshark  1
	condition:
		((#a_01_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=8
 
}