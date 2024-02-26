
rule TrojanDownloader_O97M_Donoff_QS_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.QS!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 68 69 66 74 20 3d 20 28 41 73 63 28 4d 69 64 28 6b 65 79 2c 20 28 6b 20 4d 6f 64 20 4c 65 6e 28 6b 65 79 29 29 20 2b 20 31 2c 20 31 29 29 20 4d 6f 64 20 4c 65 6e 28 73 29 29 20 2b 20 31 } //01 00  shift = (Asc(Mid(key, (k Mod Len(key)) + 1, 1)) Mod Len(s)) + 1
		$a_01_1 = {26 20 4d 69 64 28 73 2c 20 73 68 69 66 74 2c 20 31 29 } //01 00  & Mid(s, shift, 1)
		$a_01_2 = {3d 20 4d 69 64 28 73 2c 20 31 2c 20 70 6f 73 20 2d 20 31 29 20 26 20 4d 69 64 28 73 2c 20 70 6f 73 20 2b 20 31 2c 20 4c 65 6e 28 73 29 29 } //00 00  = Mid(s, 1, pos - 1) & Mid(s, pos + 1, Len(s))
	condition:
		any of ($a_*)
 
}