
rule TrojanDownloader_O97M_Ursnif_AL_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.AL!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 68 72 28 31 30 30 20 2b 20 31 30 20 2b 20 35 29 20 2b 20 22 68 22 20 2b 20 22 65 6c 6c 22 } //1 = Chr(100 + 10 + 5) + "h" + "ell"
		$a_01_1 = {2e 43 6f 6e 74 72 6f 6c 73 28 31 29 2e 54 65 78 74 } //1 .Controls(1).Text
		$a_01_2 = {2e 43 6f 6e 74 72 6f 6c 73 28 32 20 2d 20 31 20 2d 20 31 29 } //1 .Controls(2 - 1 - 1)
		$a_01_3 = {2e 4f 70 65 6e } //1 .Open
		$a_03_4 = {50 72 69 6e 74 20 23 ?? 2c 20 [0-50] 2e 54 65 78 74 } //1
		$a_01_5 = {43 6c 6f 73 65 20 23 } //1 Close #
		$a_01_6 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}