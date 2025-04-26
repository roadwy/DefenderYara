
rule TrojanDownloader_Win32_Redosdru_N_bit{
	meta:
		description = "TrojanDownloader:Win32/Redosdru.N!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {8b 55 ec 80 04 11 ?? 8b 55 ec 80 34 11 ?? 41 3b c8 7c ed } //1
		$a_01_1 = {c6 44 24 27 2f c6 44 24 28 34 c6 44 24 29 2e c6 44 24 2a 30 } //1
		$a_01_2 = {c6 44 24 0c 4b c6 44 24 0d 6f c6 44 24 0e 74 c6 44 24 0f 68 c6 44 24 10 65 } //1
		$a_03_3 = {4b c6 44 24 ?? 6f c6 44 24 ?? 74 c6 44 24 ?? 68 c6 44 24 ?? 65 c6 44 24 ?? 72 c6 44 24 ?? 35 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}