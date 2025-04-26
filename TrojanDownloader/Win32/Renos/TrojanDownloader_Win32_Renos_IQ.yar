
rule TrojanDownloader_Win32_Renos_IQ{
	meta:
		description = "TrojanDownloader:Win32/Renos.IQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {33 d2 6a 19 59 f7 f1 8b [0-03] 02 d3 80 c2 61 88 14 18 43 83 fb 03 7c } //1
		$a_01_1 = {63 3a 5c 44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 5c 46 41 42 5c d0 a0 d0 b0 d0 b1 d0 be d1 87 d0 b8 d0 b9 20 d1 81 d1 82 d0 be d0 bb 5c 4c 4c 4c 5c 52 65 6c 65 61 73 65 5c 31 2e 70 64 62 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}