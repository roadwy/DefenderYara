
rule TrojanDownloader_Win32_Genome_K{
	meta:
		description = "TrojanDownloader:Win32/Genome.K,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {30 00 00 00 8b ?? 0c 8b ?? 1c 8b ?? 08 8b ?? 20 8b ?? 38 ?? 18 75 f3 80 ?? 6b 74 07 80 ?? 4b 74 02 eb e7 } //1
		$a_01_1 = {58 30 10 50 } //1 じ倐
		$a_01_2 = {8b 53 24 03 d0 66 8b 0c 4a 8b 53 1c 03 d0 8b 1c 8a 03 c3 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}