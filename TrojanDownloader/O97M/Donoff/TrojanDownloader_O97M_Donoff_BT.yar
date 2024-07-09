
rule TrojanDownloader_O97M_Donoff_BT{
	meta:
		description = "TrojanDownloader:O97M/Donoff.BT,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {3d 20 49 6e 53 74 72 28 31 2c } //1 = InStr(1,
		$a_01_1 = {3d 20 4d 69 64 28 } //1 = Mid(
		$a_01_2 = {3d 20 4c 65 6e 28 } //1 = Len(
		$a_03_3 = {2e 53 70 61 77 6e 49 6e 73 74 61 6e 63 65 5f 0d 0a [0-0f] 2e 53 68 6f 77 57 69 6e 64 6f 77 20 3d 20 30 } //1
		$a_03_4 = {20 3d 20 47 65 74 4f 62 6a 65 63 74 28 [0-0f] 29 0d 0a [0-0f] 2e 43 72 65 61 74 65 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}