
rule TrojanDownloader_Win32_Small_AHM{
	meta:
		description = "TrojanDownloader:Win32/Small.AHM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 5c 44 6f 77 6e 54 65 6d 70 5c 2a 2e 2a } //01 00 
		$a_03_1 = {63 3a 5c 53 61 76 65 54 78 74 61 90 02 03 2e 74 78 74 90 02 04 77 90 01 03 72 90 00 } //01 00 
		$a_01_2 = {83 c9 ff 33 c0 c6 45 a8 68 c6 45 a9 74 c6 45 aa 74 c6 45 ab 70 c6 45 ac 3a c6 45 ad 2f c6 45 ae 2f c6 45 af 61 c6 45 b0 61 c6 45 b1 61 c6 45 b2 2e c6 45 b3 77 c6 45 b4 64 c6 45 b5 6a c6 45 b6 70 c6 45 b7 71 c6 45 b8 2e c6 45 b9 6e c6 45 ba 65 c6 45 bb 74 c6 45 bc 2f } //01 00 
		$a_03_3 = {88 45 c8 c6 45 c9 74 c6 45 ca 74 c6 45 cb 6e c6 45 cc 65 c6 45 ce 63 88 90 01 01 cf c6 45 d0 44 88 45 d1 90 02 04 c6 45 d3 65 c6 45 d4 6c c6 45 d5 69 c6 45 d6 46 c6 45 d7 20 c6 45 d9 61 c6 45 db 67 88 90 01 01 dc c6 45 de 50 88 45 df c6 45 e0 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}