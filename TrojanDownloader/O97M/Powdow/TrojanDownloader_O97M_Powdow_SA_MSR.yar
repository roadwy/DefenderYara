
rule TrojanDownloader_O97M_Powdow_SA_MSR{
	meta:
		description = "TrojanDownloader:O97M/Powdow.SA!MSR,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {53 68 6f 77 43 6f 6c 54 6f 4d 6f 76 65 20 22 43 3a 5c 44 69 73 6b 44 72 69 76 65 5c 31 5c 56 6f 6c 75 6d 65 5c 65 72 72 6f 72 66 69 78 2e 62 61 74 } //1 ShowColToMove "C:\DiskDrive\1\Volume\errorfix.bat
		$a_03_1 = {43 3a 5c 44 69 73 6b 44 72 69 76 65 5c 31 5c 56 6f 6c 75 6d 65 5c 42 61 63 6b 46 69 6c 65 73 5c 90 02 09 2e 6a 73 65 90 00 } //1
		$a_03_2 = {6e 64 6f 65 2e 6a 70 20 43 3a 5c 44 69 73 6b 44 72 69 76 65 5c 31 5c 56 6f 6c 75 6d 65 5c 42 61 63 6b 46 69 6c 65 73 5c 90 02 07 2e 65 78 65 90 00 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}