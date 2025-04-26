
rule TrojanDownloader_Win32_Cutwail_BZ{
	meta:
		description = "TrojanDownloader:Win32/Cutwail.BZ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 72 75 6e 5f 6d 65 6d 00 } //1
		$a_03_1 = {81 7d f8 44 41 54 41 74 ?? 81 7d f8 43 4d 44 20 74 ?? 81 7d f8 45 4e 44 2e 74 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}