
rule TrojanDownloader_Win32_Dalexis_D{
	meta:
		description = "TrojanDownloader:Win32/Dalexis.D,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 05 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 8d 34 03 8a 0e 8d 54 3d f0 8a 02 32 c8 32 c1 47 88 0e 88 02 83 ff 10 75 02 33 ff } //5
		$a_03_1 = {68 60 ea 00 00 b8 c0 d4 01 00 e8 ?? ?? ?? ?? 8b 35 ?? ?? ?? ?? 59 50 ff d6 3b df 5b 74 27 6a 0a } //5
		$a_00_2 = {2e 00 74 00 61 00 72 00 2e 00 67 00 7a 00 } //1 .tar.gz
		$a_00_3 = {68 00 65 00 6c 00 6c 00 6f 00 2e 00 6a 00 70 00 67 00 } //1 hello.jpg
		$a_00_4 = {6d 00 70 00 33 00 61 00 76 00 69 00 6d 00 70 00 67 00 6d 00 64 00 76 00 66 00 6c 00 76 00 } //1 mp3avimpgmdvflv
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*5+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=11
 
}