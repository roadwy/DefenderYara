
rule TrojanDownloader_Win32_Boaxxe{
	meta:
		description = "TrojanDownloader:Win32/Boaxxe,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {c1 e8 04 33 c2 25 0f 0f 0f 0f 33 d0 c1 e0 04 33 d8 8b c2 c1 e8 10 33 c3 25 ff ff 00 00 } //1
		$a_01_1 = {8b 33 8b 3b 8b ce c1 e9 1d c1 ee 1e 83 e1 01 83 e6 01 c1 ef 1f } //1
		$a_01_2 = {0f b7 3a 8b df 81 e3 00 f0 ff ff 81 fb 00 30 00 00 75 0c 8b 5d 08 81 e7 ff 0f 00 00 01 1c 37 8b 78 04 ff 45 fc 83 ef 08 d1 ef 83 c2 02 39 7d fc 72 ce } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}