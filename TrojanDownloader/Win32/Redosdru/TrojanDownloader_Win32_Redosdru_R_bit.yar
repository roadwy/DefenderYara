
rule TrojanDownloader_Win32_Redosdru_R_bit{
	meta:
		description = "TrojanDownloader:Win32/Redosdru.R!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 8a 14 01 80 c2 90 01 01 88 14 01 8b 45 fc 8a 14 01 80 f2 90 01 01 88 14 01 41 3b ce 7c 90 00 } //1
		$a_01_1 = {8a 14 01 8b da 81 e3 ff 00 00 00 03 f3 81 e6 ff 00 00 80 79 08 4e 81 ce 00 ff ff ff 46 8a 1c 06 88 54 24 18 88 1c 01 8b 5c 24 18 88 14 06 33 d2 8a 14 01 81 e3 ff 00 00 00 03 d3 81 e2 ff 00 00 80 79 08 4a 81 ca 00 ff ff ff 42 8a 14 02 8a 1c 2f 32 da 8b 54 24 1c 88 1c 2f 47 3b fa 72 } //1
		$a_01_2 = {00 4b 6f 74 68 65 72 35 39 39 00 } //1
		$a_01_3 = {00 44 6c 6c 46 75 55 70 67 72 61 64 72 73 00 } //1
		$a_01_4 = {00 44 68 6c 4d 65 6d 56 65 72 73 67 74 00 } //1 䐀汨敍噭牥杳t
		$a_01_5 = {00 47 65 74 6f 6e 67 35 33 38 00 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}