
rule TrojanDownloader_Win32_Banload_BFM{
	meta:
		description = "TrojanDownloader:Win32/Banload.BFM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_01_0 = {54 65 73 74 4c 6f 61 64 5c 00 } //1 敔瑳潌摡\
		$a_01_1 = {43 3a 5c 54 45 53 54 45 2e 44 41 54 } //1 C:\TESTE.DAT
		$a_01_2 = {70 6b 62 61 63 6b 23 20 00 } //1
		$a_01_3 = {5c 56 42 6f 78 4d 69 6e 69 52 64 72 44 4e } //1 \VBoxMiniRdrDN
		$a_01_4 = {51 37 48 71 53 33 } //1 Q7HqS3
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=4
 
}