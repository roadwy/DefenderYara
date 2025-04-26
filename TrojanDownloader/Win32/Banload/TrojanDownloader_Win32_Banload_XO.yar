
rule TrojanDownloader_Win32_Banload_XO{
	meta:
		description = "TrojanDownloader:Win32/Banload.XO,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 03 00 00 "
		
	strings :
		$a_01_0 = {43 42 78 46 6e 6c 7a } //4 CBxFnlz
		$a_01_1 = {54 6d 72 56 72 66 63 } //4 TmrVrfc
		$a_01_2 = {54 00 46 00 52 00 4d 00 55 00 4e 00 53 00 } //2 TFRMUNS
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*4+(#a_01_2  & 1)*2) >=10
 
}