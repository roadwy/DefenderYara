
rule TrojanDownloader_BAT_Bladabindi_NITA_MTB{
	meta:
		description = "TrojanDownloader:BAT/Bladabindi.NITA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {72 d9 01 00 70 28 ?? 00 00 06 72 ca 02 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 2c 07 16 28 ?? 00 00 0a 2a 72 d9 01 00 70 28 ?? 00 00 06 72 ca 02 00 70 28 ?? 00 00 0a 72 e4 02 00 70 28 ?? 00 00 0a 20 dc 05 00 00 28 ?? 00 00 0a 28 ?? 00 00 06 20 d0 07 00 00 28 ?? 00 00 0a 72 d9 01 00 70 28 ?? 00 00 06 72 b8 02 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 06 72 f0 02 00 70 72 f4 02 00 70 6f 6a 00 00 0a 0b 07 28 ?? 00 00 0a 0c 20 78 05 00 00 28 ?? 00 00 0a 72 d9 01 00 70 28 ?? 00 00 06 72 f9 01 00 70 28 ?? 00 00 0a 08 28 ?? 00 00 0a 20 b8 0b 00 00 28 ?? 00 00 0a 28 ?? 00 00 06 20 78 05 00 00 28 ?? 00 00 0a 16 28 ?? 00 00 0a 2a } //2
		$a_01_1 = {44 6f 77 6e 6c 6f 61 64 46 69 6c 65 } //1 DownloadFile
		$a_01_2 = {57 72 69 74 65 41 6c 6c 42 79 74 65 73 } //1 WriteAllBytes
	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}