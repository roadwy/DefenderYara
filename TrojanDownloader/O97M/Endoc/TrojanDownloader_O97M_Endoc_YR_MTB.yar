
rule TrojanDownloader_O97M_Endoc_YR_MTB{
	meta:
		description = "TrojanDownloader:O97M/Endoc.YR!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6f 77 65 72 73 68 65 6c 6c 2e 65 78 65 20 2d 43 6f 6d 6d 61 6e 64 20 49 45 58 20 28 4e 65 77 2d 4f 62 6a 65 63 74 28 27 4e 65 74 2e 57 65 62 43 6c 69 65 6e 74 27 29 29 2e 27 44 6f 57 6e 6c 6f } //1 owershell.exe -Command IEX (New-Object('Net.WebClient')).'DoWnlo
		$a_00_1 = {73 70 61 63 65 6d 61 6e 74 72 61 2e 62 69 7a 2f 62 6c 79 61 74 } //1 spacemantra.biz/blyat
		$a_00_2 = {64 73 54 72 49 6e 47 27 28 27 } //1 dsTrInG'('
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}