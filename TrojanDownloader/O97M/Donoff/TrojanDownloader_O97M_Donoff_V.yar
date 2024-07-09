
rule TrojanDownloader_O97M_Donoff_V{
	meta:
		description = "TrojanDownloader:O97M/Donoff.V,SIGNATURE_TYPE_MACROHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {2f 62 6c 6f 62 3f 64 6f 77 6e 22 } //1 /blob?down"
		$a_01_1 = {20 3d 20 22 67 65 2e 74 74 2f 61 70 69 2f 31 2f 66 69 6c 65 73 2f } //1  = "ge.tt/api/1/files/
		$a_01_2 = {3d 20 45 6e 76 69 72 6f 6e 28 22 54 65 6d 70 22 29 20 26 20 22 5c 22 20 26 20 22 4d 61 63 72 6f 43 6f 64 65 22 } //1 = Environ("Temp") & "\" & "MacroCode"
		$a_01_3 = {52 4e 4f 44 4b 45 53 58 30 20 2b 20 52 4e 4f 44 4b 45 53 58 } //1 RNODKESX0 + RNODKESX
		$a_02_4 = {20 2b 20 22 2e 22 0d 0a [0-15] 20 3d 20 90 05 10 06 61 2d 7a 30 2d 39 20 2b 20 22 65 22 0d 0a [0-15] 20 3d 20 90 05 10 06 61 2d 7a 30 2d 39 20 2b 20 22 78 22 0d 0a [0-15] 20 3d 20 90 05 10 06 61 2d 7a 30 2d 39 20 2b 20 22 65 22 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_02_4  & 1)*1) >=3
 
}