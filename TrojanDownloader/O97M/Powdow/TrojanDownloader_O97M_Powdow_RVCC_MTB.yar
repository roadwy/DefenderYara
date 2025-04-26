
rule TrojanDownloader_O97M_Powdow_RVCC_MTB{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 61 6c 6c 76 62 61 2e 73 68 65 6c 6c 24 28 78 78 78 78 78 78 61 29 65 6e 64 73 75 62 } //1 callvba.shell$(xxxxxxa)endsub
		$a_01_1 = {78 78 78 78 78 78 61 3d 31 31 31 2e 31 31 31 2e 63 6f 6e 74 72 6f 6c 74 69 70 74 65 78 74 2b 31 31 31 2e 31 31 32 2e 74 61 67 2b 31 31 31 2e 31 31 33 2e 63 6f 6e 74 72 6f 6c 74 69 70 74 65 78 74 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 3a 64 65 62 75 67 2e 70 72 69 6e 74 } //1 xxxxxxa=111.111.controltiptext+111.112.tag+111.113.controltiptext:::::::::::::::::::::::::debug.print
		$a_01_2 = {77 6f 72 6b 62 6f 6f 6b 5f 6f 70 65 6e 28 29 3a 3a } //1 workbook_open()::
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule TrojanDownloader_O97M_Powdow_RVCC_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Powdow.RVCC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {61 75 74 6f 5f 6f 70 65 6e 28 29 69 6d 61 67 65 6d 73 69 6d 70 6c 65 73 63 64 74 3d 22 68 74 74 70 73 3a 2f 2f 77 77 77 2e 34 73 79 6e 63 2e 63 6f 6d 2f 77 65 62 2f 64 69 72 65 63 74 64 6f 77 6e 6c 6f 61 64 2f ?? ?? ?? ?? ?? ?? ?? ?? 2f ?? ?? ?? ?? ?? ?? ?? ?? 2e ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 22 72 65 6e 61 6e 63 64 74 3d 22 63 3a 5c 75 73 65 72 73 5c 70 75 62 6c 69 63 5c 22 75 72 6c 64 6f 77 6e 6c 6f 61 64 74 6f 66 69 6c 65 30 } //1
		$a_01_1 = {73 68 65 6c 6c 28 6d 5f 73 2b 69 6e 67 72 69 64 63 64 74 2b 6d 5f 73 31 2b 6d 5f 73 32 2b 6d 5f 73 33 29 2c 30 65 6e 64 73 75 62 } //1 shell(m_s+ingridcdt+m_s1+m_s2+m_s3),0endsub
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}