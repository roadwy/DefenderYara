
rule Trojan_Win64_Filecoder_QZ_MTB{
	meta:
		description = "Trojan:Win64/Filecoder.QZ!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {68 31 3a 4c 59 44 55 64 51 42 7a 57 50 67 43 4f 75 77 6f 47 6c 33 71 50 45 43 69 4b 58 77 71 45 30 2b 74 41 39 4a 4d 31 6b 76 49 70 66 77 3d } //2 h1:LYDUdQBzWPgCOuwoGl3qPECiKXwqE0+tA9JM1kvIpfw=
		$a_01_1 = {6d 61 69 6e 2e 73 65 74 57 61 6c 6c 70 61 70 65 72 } //2 main.setWallpaper
		$a_01_2 = {50 72 69 6e 63 65 2d 52 61 6e 73 6f 6d 77 61 72 65 2f 66 69 6c 65 77 61 6c 6b 65 72 2e 45 6e 63 72 79 70 74 44 69 72 65 63 74 6f 72 79 } //2 Prince-Ransomware/filewalker.EncryptDirectory
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}