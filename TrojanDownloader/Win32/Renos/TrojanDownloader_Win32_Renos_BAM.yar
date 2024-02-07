
rule TrojanDownloader_Win32_Renos_BAM{
	meta:
		description = "TrojanDownloader:Win32/Renos.BAM,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {6d 61 64 43 72 79 70 74 00 } //01 00 
		$a_01_1 = {4b 4f 4c 48 54 54 50 44 6f 77 6e 6c 6f 61 64 00 } //01 00  佋䡌呔䑐睯汮慯d
		$a_01_2 = {54 6c 48 65 6c 70 33 32 00 } //01 00 
		$a_01_3 = {4d 50 47 55 6e 5a 49 50 00 } //01 00 
		$a_01_4 = {4d 79 41 55 74 69 6c 73 00 } //01 00 
		$a_01_5 = {41 64 77 61 72 65 55 74 69 6c 73 00 } //03 00  摁慷敲瑕汩s
		$a_01_6 = {a1 b8 92 71 8c ef 11 de e1 78 17 73 cb 15 80 a8 67 52 60 a7 65 71 97 2a } //03 00 
		$a_01_7 = {f3 50 d2 b7 eb 7c 0a eb c3 66 3d f6 50 80 62 85 78 d6 20 e1 0d c1 19 79 16 20 b6 16 8e ef 6d dc } //00 00 
	condition:
		any of ($a_*)
 
}
rule TrojanDownloader_Win32_Renos_BAM_2{
	meta:
		description = "TrojanDownloader:Win32/Renos.BAM,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 09 00 00 01 00 "
		
	strings :
		$a_00_0 = {77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 } //01 00  ws\CurrentVersion\Run
		$a_80_1 = {26 61 66 66 69 64 3d } //&affid=  01 00 
		$a_00_2 = {69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2f 00 77 00 73 00 2e 00 7a 00 69 00 70 00 } //01 00  install/ws.zip
		$a_00_3 = {77 69 6e 77 65 62 73 65 63 75 72 69 74 79 2e 63 6f 6d } //01 00  winwebsecurity.com
		$a_00_4 = {32 00 2e 00 20 00 43 00 68 00 65 00 63 00 6b 00 69 00 6e 00 67 00 20 00 66 00 6f 00 72 00 20 00 74 00 68 00 65 00 20 00 6c 00 61 00 74 00 65 00 73 00 74 00 20 00 63 00 6f 00 6d 00 70 00 6f 00 6e 00 65 00 6e 00 74 00 73 00 2e 00 2e 00 2e 00 } //01 00  2. Checking for the latest components...
		$a_00_5 = {33 00 2e 00 20 00 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 69 00 6e 00 67 00 20 00 74 00 68 00 65 00 20 00 6c 00 61 00 74 00 65 00 73 00 74 00 20 00 63 00 6f 00 6d 00 70 00 6f 00 6e 00 65 00 6e 00 74 00 73 00 2e 00 2e 00 2e 00 } //01 00  3. Downloading the latest components...
		$a_00_6 = {41 00 44 00 5f 00 49 00 4c 00 06 00 43 00 4f 00 4e 00 46 00 49 00 47 00 } //02 00 
		$a_01_7 = {61 6e 74 69 20 76 69 72 75 73 65 73 20 63 68 65 63 68 21 } //02 00  anti viruses chech!
		$a_01_8 = {81 3e 50 4b 01 02 74 0a b8 f6 ff ff ff e9 } //00 00 
	condition:
		any of ($a_*)
 
}