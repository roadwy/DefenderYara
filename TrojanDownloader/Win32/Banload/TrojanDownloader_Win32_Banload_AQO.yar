
rule TrojanDownloader_Win32_Banload_AQO{
	meta:
		description = "TrojanDownloader:Win32/Banload.AQO,SIGNATURE_TYPE_PEHSTR_EXT,1e 00 15 00 05 00 00 "
		
	strings :
		$a_03_0 = {7d 28 8b 45 fc 33 d2 b9 04 00 00 00 f7 f1 0f b6 92 ?? ?? 40 00 8b 45 08 03 45 fc 0f b6 08 33 ca 8b 55 08 03 55 fc 88 0a eb c7 } //1
		$a_03_1 = {7d 26 8b 45 fc 33 d2 6a 04 59 f7 f1 0f b6 82 ?? ?? 40 00 8b 4d 08 03 4d fc 0f b6 09 33 c8 8b 45 08 03 45 fc 88 08 eb cb } //1
		$a_01_2 = {67 71 bd fe 4d 70 bd e4 67 72 ad e7 50 78 e1 e4 42 66 } //10
		$a_01_3 = {0d 21 e1 a4 0a 3b fe a4 15 26 00 } //10
		$a_01_4 = {5a 77 ac f3 5e 73 a8 ff 52 7f a4 fb 56 7b a0 e7 4a 67 bc e3 4e 63 b8 ef 42 6f ff a6 09 26 fb a2 } //10
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*10+(#a_01_3  & 1)*10+(#a_01_4  & 1)*10) >=21
 
}