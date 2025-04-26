
rule TrojanDownloader_O97M_Donoff_PW{
	meta:
		description = "TrojanDownloader:O97M/Donoff.PW,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {22 2a 26 38 37 38 37 33 6a 6e 68 6a 68 73 4a 4a 48 47 47 46 3d 3d 2b 2b 2b 22 } //1 "*&87873jnhjhsJJHGGF==+++"
		$a_01_1 = {22 48 47 48 47 68 77 65 67 72 62 63 65 37 34 35 34 36 35 36 37 22 } //1 "HGHGhwegrbce74546567"
		$a_01_2 = {22 33 34 38 35 65 72 6a 74 67 68 68 67 46 44 46 44 47 4a 4b 4a 68 6a 68 65 22 } //1 "3485erjtghhgFDFDGJKJhjhe"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}