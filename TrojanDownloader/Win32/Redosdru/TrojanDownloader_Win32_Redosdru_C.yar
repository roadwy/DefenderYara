
rule TrojanDownloader_Win32_Redosdru_C{
	meta:
		description = "TrojanDownloader:Win32/Redosdru.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 04 00 00 "
		
	strings :
		$a_03_0 = {4b c6 44 24 ?? 6f c6 44 24 ?? 74 c6 44 24 ?? 68 c6 44 24 ?? 65 c6 44 24 ?? 72 c6 44 24 ?? 35 } //1
		$a_03_1 = {6a 00 80 04 06 ?? ff d7 8b 44 24 0c 8a 14 06 80 f2 ?? 88 14 06 46 3b f3 7c } //1
		$a_01_2 = {c6 44 24 1b 4e c6 44 24 1d 4c c6 44 24 1e 33 c6 44 24 1f 32 c6 44 24 20 2e c6 44 24 21 64 c6 44 24 24 00 c6 44 24 0d 73 c6 44 24 0e 74 c6 44 24 0f 72 c6 44 24 11 65 c6 44 24 12 6e c6 44 24 13 41 } //1
		$a_01_3 = {c6 45 e0 4d c6 45 e1 6f c6 45 e2 7a 88 55 e3 88 45 e4 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=2
 
}