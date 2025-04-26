
rule TrojanDownloader_Win64_Vityce_B_bit{
	meta:
		description = "TrojanDownloader:Win64/Vityce.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 00 64 00 79 00 76 00 38 00 73 00 6c 00 37 00 65 00 77 00 71 00 31 00 77 00 2e 00 63 00 6c 00 6f 00 75 00 64 00 66 00 72 00 6f 00 6e 00 74 00 2e 00 6e 00 65 00 74 00 2f 00 69 00 31 00 2f 00 72 00 31 00 2e 00 70 00 68 00 70 00 } //2 ddyv8sl7ewq1w.cloudfront.net/i1/r1.php
		$a_01_1 = {47 00 6c 00 6f 00 62 00 61 00 6c 00 5c 00 46 00 61 00 73 00 74 00 50 00 72 00 69 00 6e 00 74 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 } //1 Global\FastPrintServices
		$a_01_2 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 46 00 61 00 73 00 74 00 20 00 50 00 72 00 69 00 6e 00 74 00 20 00 53 00 65 00 72 00 76 00 69 00 63 00 65 00 73 00 } //1 SOFTWARE\Microsoft\Fast Print Services
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}