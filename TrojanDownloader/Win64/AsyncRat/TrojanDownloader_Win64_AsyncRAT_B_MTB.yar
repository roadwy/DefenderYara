
rule TrojanDownloader_Win64_AsyncRAT_B_MTB{
	meta:
		description = "TrojanDownloader:Win64/AsyncRAT.B!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 79 39 77 59 58 4e 30 5a 53 35 6d 62 79 39 79 59 58 63 76 4e } //2 Ly9wYXN0ZS5mby9yYXcvN
		$a_01_1 = {61 74 74 72 69 62 20 2b 68 } //2 attrib +h
		$a_01_2 = {5c 00 2e 00 5c 00 50 00 68 00 79 00 73 00 69 00 63 00 61 00 6c 00 44 00 72 00 69 00 76 00 65 00 30 00 } //2 \.\PhysicalDrive0
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}