
rule TrojanDownloader_Win32_Lerspeng_B{
	meta:
		description = "TrojanDownloader:Win32/Lerspeng.B,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 04 00 00 "
		
	strings :
		$a_01_0 = {6d 73 73 00 2e 65 78 65 00 } //1
		$a_03_1 = {50 57 ff 15 90 01 04 83 f8 01 74 90 03 01 01 0c 0f 83 c6 04 90 03 05 05 83 fe 90 01 01 81 fe 90 01 04 0f 82 90 01 01 ff ff ff 90 00 } //1
		$a_03_2 = {8d 45 fc 50 8d 85 90 01 02 ff ff 50 ff 15 90 01 04 83 f8 01 75 90 01 01 39 7d fc 74 06 83 7d fc 06 75 90 00 } //1
		$a_01_3 = {69 c0 01 01 01 01 57 8b 7d 08 c1 e9 02 f3 ab 8b ce 83 e1 03 f3 aa } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=1
 
}