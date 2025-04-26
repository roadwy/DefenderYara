
rule TrojanDownloader_Win32_Genome_AK{
	meta:
		description = "TrojanDownloader:Win32/Genome.AK,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 6b 75 67 6f 75 5f 31 34 37 31 2e 65 78 65 } //1 /kugou_1471.exe
		$a_01_1 = {2f 50 41 52 54 4e 45 52 32 30 33 39 2e 65 78 65 } //1 /PARTNER2039.exe
		$a_01_2 = {5a 67 68 76 66 6a 76 49 6d 76 6b 4c 6b 67 67 53 } //1 ZghvfjvImvkLkggS
		$a_01_3 = {76 6f 79 7a 6f 72 7a 65 5a 7a 67 7a 57 62 69 76 66 4a 67 76 6d 69 76 67 6d 52 } //1 voyzorzeZzgzWbivfJgvmivgmR
		$a_01_4 = {2e 7a 67 75 77 61 6e 67 2e 63 6f 6d 2f 73 6f 66 74 2f 61 33 70 2f 50 50 54 56 28 70 70 6c 69 76 65 29 68 65 69 6d 61 5f 30 30 32 30 2e 65 78 65 } //1 .zguwang.com/soft/a3p/PPTV(pplive)heima_0020.exe
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}