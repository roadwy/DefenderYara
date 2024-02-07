
rule TrojanDownloader_Win32_Beshe_A{
	meta:
		description = "TrojanDownloader:Win32/Beshe.A,SIGNATURE_TYPE_PEHSTR,2c 00 2c 00 08 00 00 0a 00 "
		
	strings :
		$a_01_0 = {43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 70 6f 6c 69 63 69 65 73 00 00 65 78 70 6c 6f 72 65 72 00 00 00 00 72 75 6e 00 53 68 65 62 65 } //0a 00 
		$a_01_1 = {45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 00 48 69 64 64 65 6e 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 45 78 70 6c 6f 72 65 72 5c 41 64 76 61 6e 63 65 64 5c 46 6f 6c 64 65 72 5c 48 69 64 64 65 6e 5c 53 48 4f 57 41 4c 4c 00 00 00 43 68 65 63 6b 65 64 56 61 6c 75 65 } //0a 00 
		$a_01_2 = {73 68 65 6c 6c 5c 6f 70 65 6e 3d b4 f2 bf aa 28 26 4f 29 00 ff ff ff ff 1b 00 00 00 73 68 65 6c 6c 5c 6f 70 65 6e 5c 43 6f 6d 6d 61 6e 64 3d 74 65 73 74 2e 65 78 65 } //0a 00 
		$a_01_3 = {4f 70 65 6e 20 48 74 74 70 3a 2f 2f 78 69 61 7a 61 69 2e 31 39 36 34 36 32 30 33 35 2e 63 6e 2f 74 6a 2e 61 73 70 } //01 00  Open Http://xiazai.196462035.cn/tj.asp
		$a_01_4 = {61 75 74 6f 72 75 6e 2e 69 6e 66 } //01 00  autorun.inf
		$a_01_5 = {4f 75 74 5c 61 6e 74 69 61 75 74 6f 72 75 6e } //01 00  Out\antiautorun
		$a_01_6 = {46 6c 6f 77 65 72 2e 64 6c 6c } //01 00  Flower.dll
		$a_01_7 = {63 6f 6e 66 69 67 5c 73 79 73 74 65 6d 70 72 6f 66 69 6c 65 5c 76 69 73 74 61 2e 65 78 65 } //00 00  config\systemprofile\vista.exe
	condition:
		any of ($a_*)
 
}