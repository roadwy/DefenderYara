
rule TrojanDownloader_O97M_EncDoc_CLC_MTB{
	meta:
		description = "TrojanDownloader:O97M/EncDoc.CLC!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {68 74 74 70 3a 2f 2f [0-04] 72 61 68 6f 74 61 62 61 64 6f 6c 2e 63 6f 2e 69 72 2f 73 6e 65 79 76 65 78 76 2f [0-04] 6a 70 67 } //1
		$a_01_1 = {43 3a 5c 41 75 74 6f 43 61 64 65 73 74 5c 41 75 74 6f 43 61 64 65 73 74 32 5c 46 69 6b 73 61 74 2e 65 78 65 } //1 C:\AutoCadest\AutoCadest2\Fiksat.exe
		$a_01_2 = {43 3a 5c 41 75 74 6f 43 61 64 65 73 74 5c 41 75 74 6f 43 61 64 65 73 74 32 5c 46 69 6b 73 61 74 2e 64 6c 6c } //1 C:\AutoCadest\AutoCadest2\Fiksat.dll
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}