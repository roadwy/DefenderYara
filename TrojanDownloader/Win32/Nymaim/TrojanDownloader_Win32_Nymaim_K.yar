
rule TrojanDownloader_Win32_Nymaim_K{
	meta:
		description = "TrojanDownloader:Win32/Nymaim.K,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 d3 8a 16 30 1e 46 01 fb c1 c3 08 49 75 f1 } //1
		$a_01_1 = {32 06 46 88 07 8b 5d f4 8b 4d f8 89 ca 83 e1 03 c1 e1 03 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}