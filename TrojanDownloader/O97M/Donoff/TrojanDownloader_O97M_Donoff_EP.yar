
rule TrojanDownloader_O97M_Donoff_EP{
	meta:
		description = "TrojanDownloader:O97M/Donoff.EP,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {28 30 29 20 3d 20 22 77 73 63 72 69 22 } //1 (0) = "wscri"
		$a_01_1 = {28 31 29 20 3d 20 22 70 74 2e 73 22 } //1 (1) = "pt.s"
		$a_01_2 = {28 32 29 20 3d 20 22 68 65 6c 6c 22 } //1 (2) = "hell"
		$a_03_3 = {3d 20 4a 6f 69 6e 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-0a] 2c 20 22 22 29 0d 0a 27 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}