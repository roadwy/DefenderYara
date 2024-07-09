
rule TrojanDownloader_Win32_Redosdru_D_bit{
	meta:
		description = "TrojanDownloader:Win32/Redosdru.D!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {7e 17 8b 45 fc 80 04 08 7a 03 c1 8b 45 fc 80 34 08 59 03 c1 41 3b ce 7c e9 } //2
		$a_01_1 = {8a 14 32 88 10 8b 55 fc 88 19 8b 4d 0c 0f b6 00 03 ca 0f b6 d3 03 c2 8b df 99 f7 fb 8a 04 32 30 01 ff 45 fc 8b 45 fc 3b 45 10 72 } //2
		$a_03_2 = {c6 45 f4 4b [0-08] c6 45 f5 6f c6 45 f6 74 c6 45 f7 68 c6 45 f8 65 c6 45 f9 72 c6 45 fa 35 c6 45 fb 39 c6 45 fc 39 } //1
		$a_01_3 = {c6 45 e8 43 c6 45 e9 3a c6 45 ea 5c c6 45 eb 50 c6 45 ec 72 c6 45 ed 6f c6 45 ee 67 c6 45 ef 72 c6 45 f0 61 c6 45 f1 6d c6 45 f2 20 c6 45 f3 46 c6 45 f4 69 c6 45 f5 6c c6 45 f6 65 c6 45 f7 73 c6 45 f8 5c } //1
		$a_03_4 = {ff ff 4d c6 85 ?? ?? ff ff 6f c6 85 ?? ?? ff ff 7a c6 85 ?? ?? ff ff 69 c6 85 ?? ?? ff ff 6c c6 85 ?? ?? ff ff 6c c6 85 ?? ?? ff ff 61 c6 85 ?? ?? ff ff 2f c6 85 ?? ?? ff ff 34 c6 85 ?? ?? ff ff 2e } //1
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1) >=3
 
}