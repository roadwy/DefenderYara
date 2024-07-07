
rule TrojanDownloader_Win32_Redosdru_SIB_MTB{
	meta:
		description = "TrojanDownloader:Win32/Redosdru.SIB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 c9 85 c0 7e 90 01 01 90 02 05 8b 54 24 90 01 01 8a 1c 11 80 c3 90 01 01 88 1c 11 8b 54 24 90 1b 02 8a 1c 11 80 f3 90 01 01 88 1c 11 41 3b c8 7c 90 01 01 8b 44 24 90 00 } //1
		$a_02_1 = {8b 6c 24 18 41 81 e1 90 01 04 79 90 01 01 49 81 c9 90 01 04 41 8a 14 01 8b da 81 e3 90 01 04 03 f3 81 e6 90 01 04 79 90 01 01 4e 81 ce 90 01 04 46 8a 1c 06 88 54 24 18 88 1c 01 8b 5c 24 18 88 14 06 33 d2 8a 14 01 81 e3 90 01 04 03 d3 81 e2 90 01 04 79 90 01 01 4a 81 ca 90 01 04 42 8a 14 02 8a 1c 2f 32 da 8b 54 24 1c 88 1c 2f 47 3b fa 72 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}