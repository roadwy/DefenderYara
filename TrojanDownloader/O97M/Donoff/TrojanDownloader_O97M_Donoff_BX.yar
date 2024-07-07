
rule TrojanDownloader_O97M_Donoff_BX{
	meta:
		description = "TrojanDownloader:O97M/Donoff.BX,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {77 68 61 74 69 73 64 61 73 20 3d 20 6d 61 73 68 69 6e 61 28 77 68 61 74 69 73 64 61 73 2c 20 22 90 02 08 22 2c 20 22 4d 22 29 90 00 } //1
		$a_03_1 = {77 68 61 74 69 73 64 61 73 20 3d 20 6d 61 73 68 69 6e 61 28 22 90 02 08 69 63 72 6f 90 02 08 6f 66 74 2e 58 90 02 08 4c 48 54 54 50 90 02 08 41 64 6f 64 62 90 00 } //1
		$a_01_2 = {53 65 74 20 68 61 73 48 61 73 48 61 73 5f 74 6f 5f 66 69 64 64 6c 65 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 73 6f 6d 65 62 6f 64 79 42 6c 6f 6f 64 79 28 32 29 29 } //1 Set hasHasHas_to_fiddle = CreateObject(somebodyBloody(2))
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}