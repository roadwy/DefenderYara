
rule TrojanDownloader_Win32_Zlob_ZWR{
	meta:
		description = "TrojanDownloader:Win32/Zlob.ZWR,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {25 00 00 00 dc c0 c0 c4 8e 9b 9b d7 c6 d1 d5 c0 db da c4 c6 db de d1 d7 c0 c7 9a d7 db d9 9b d0 c6 c2 87 86 9a d0 d5 c0 d5 00 00 } //1
		$a_01_1 = {6a 00 8d 45 c4 b9 68 ad 41 00 8b 15 fc 12 42 00 e8 01 9d fe ff 8b 45 c4 e8 09 9e fe ff 50 a1 fc 12 42 00 e8 fe 9d fe ff 50 e8 78 b1 fe ff 33 c0 89 45 f8 8b 45 fc 03 c0 83 c0 09 89 45 fc } //1
		$a_01_2 = {ff 35 fc 12 42 00 68 78 ad 41 00 8d 4d bc b2 b4 b8 84 ad 41 00 e8 a6 8a ff ff ff 75 bc 8d 45 c0 ba 03 00 00 00 e8 92 9b fe ff 8b 45 c0 e8 c2 d5 ff ff 33 c0 89 45 f8 8b 45 fc 03 c0 83 c0 09 89 45 fc 83 45 fc 7b } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}