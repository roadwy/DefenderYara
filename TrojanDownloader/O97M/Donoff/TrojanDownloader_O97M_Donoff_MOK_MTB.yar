
rule TrojanDownloader_O97M_Donoff_MOK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Donoff.MOK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {6b 6f 6b 6f 20 5f } //1 koko _
		$a_01_1 = {22 6d 22 20 5f } //1 "m" _
		$a_01_2 = {22 73 22 20 5f } //1 "s" _
		$a_01_3 = {22 68 22 20 5f } //1 "h" _
		$a_01_4 = {22 74 22 20 5f } //1 "t" _
		$a_01_5 = {28 30 2c 20 22 6f 70 65 6e 22 2c 20 6b 6f 6b 6f 2c 20 22 68 22 20 5f } //1 (0, "open", koko, "h" _
		$a_01_6 = {2b 20 22 77 22 20 2b 20 22 2e 22 20 2b 20 22 62 22 20 2b 20 22 69 22 20 2b 20 22 74 22 20 2b 20 22 6c 22 20 2b 20 22 79 22 20 2b 20 22 2e 22 20 2b 20 22 63 22 20 2b 20 22 6f 22 20 2b 20 22 6d 2f 68 77 64 69 6e 6e 77 73 68 64 77 64 77 64 77 71 77 68 64 61 22 } //1 + "w" + "." + "b" + "i" + "t" + "l" + "y" + "." + "c" + "o" + "m/hwdinnwshdwdwdwqwhda"
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}