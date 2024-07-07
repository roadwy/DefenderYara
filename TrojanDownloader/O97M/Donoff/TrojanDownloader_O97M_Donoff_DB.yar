
rule TrojanDownloader_O97M_Donoff_DB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.DB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 06 00 00 "
		
	strings :
		$a_00_0 = {68 62 6d 20 3d 20 55 73 65 72 46 6f 72 6d 31 2e 90 02 15 2e 74 65 78 74 } //1
		$a_01_1 = {6b 6a 69 20 3d 20 55 73 65 72 46 6f 72 6d 31 2e 90 02 15 2e 54 65 78 74 } //1
		$a_01_2 = {53 68 65 6c 6c 20 28 22 63 6d 64 2e 65 78 65 20 2f 63 20 22 20 2b 20 } //1 Shell ("cmd.exe /c " + 
		$a_01_3 = {68 5e 74 5e 74 70 5e 73 3a 2f 2f } //1 h^t^tp^s://
		$a_01_4 = {44 6f 5e 77 6e 6c 5e 6f 61 64 46 69 5e 6c 65 } //1 Do^wnl^oadFi^le
		$a_01_5 = {2d 77 69 5e 6e 64 6f 5e 77 73 74 79 6c 65 20 68 5e 69 64 64 5e 65 6e } //1 -wi^ndo^wstyle h^idd^en
	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=3
 
}