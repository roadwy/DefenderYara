
rule TrojanDownloader_Win32_Renos_gen_AK{
	meta:
		description = "TrojanDownloader:Win32/Renos.gen!AK,SIGNATURE_TYPE_PEHSTR,04 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {89 11 8b 45 f8 0f be 08 8b 55 fc c1 e2 04 8b 45 08 8b 54 10 08 c1 ea 08 0f be c2 33 c8 8b 55 f8 88 0a 8b 45 f8 0f be 08 85 c9 75 60 } //1
		$a_01_1 = {8b 48 3c 8b 55 08 8d 44 0a 18 89 45 f8 8b 4d f8 8b 55 08 03 51 60 89 55 f4 8b 45 0c c1 e8 10 25 ff ff 00 00 25 ff ff 00 00 85 c0 75 14 } //1
		$a_01_2 = {25 ff 03 00 00 89 45 d8 83 7d d8 07 74 2c 83 7d d8 0a 74 14 83 7d d8 0c 74 56 83 7d d8 10 74 3e 83 7d d8 15 74 26 } //2
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*2) >=3
 
}