
rule TrojanDownloader_BAT_RedNet_CCJZ_MTB{
	meta:
		description = "TrojanDownloader:BAT/RedNet.CCJZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 00 72 00 69 00 76 00 65 00 2e 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 2e 00 63 00 6f 00 6d 00 2f 00 75 00 63 00 3f 00 65 00 78 00 70 00 6f 00 72 00 74 00 3d 00 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 26 00 69 00 64 00 3d 00 31 00 64 00 68 00 45 00 30 00 61 00 51 00 64 00 30 00 6b 00 51 00 77 00 49 00 4e 00 49 00 45 00 38 00 38 00 68 00 48 00 52 00 35 00 38 00 57 00 4b 00 71 00 32 00 44 00 66 00 58 00 62 00 76 00 4c 00 } //2 drive.google.com/uc?export=download&id=1dhE0aQd0kQwINIE88hHR58WKq2DfXbvL
		$a_01_1 = {46 00 74 00 79 00 34 00 72 00 42 00 6a 00 39 00 51 00 59 00 6f 00 3d 00 } //2 Fty4rBj9QYo=
		$a_01_2 = {47 00 5a 00 53 00 63 00 6b 00 77 00 4e 00 6b 00 33 00 72 00 51 00 35 00 63 00 68 00 4d 00 4e 00 62 00 77 00 61 00 66 00 7a 00 67 00 3d 00 3d 00 } //1 GZSckwNk3rQ5chMNbwafzg==
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}