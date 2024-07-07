
rule TrojanDownloader_O97M_Ursnif_AJ_MTB{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.AJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 90 02 10 20 26 20 90 02 30 2e 78 73 6c 22 2c 20 31 29 90 00 } //1
		$a_03_1 = {26 20 43 68 72 28 90 02 08 28 90 02 08 28 90 02 08 29 2c 90 00 } //1
		$a_01_2 = {56 42 41 2e 49 6e 74 65 72 61 63 74 69 6f 6e 2e 53 68 65 6c 6c } //1 VBA.Interaction.Shell
		$a_01_3 = {3d 20 22 62 69 6e 2e 62 61 73 65 36 34 22 } //1 = "bin.base64"
		$a_01_4 = {2e 76 61 6c 75 65 } //1 .value
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}
rule TrojanDownloader_O97M_Ursnif_AJ_MTB_2{
	meta:
		description = "TrojanDownloader:O97M/Ursnif.AJ!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,08 00 08 00 08 00 00 "
		
	strings :
		$a_01_0 = {3d 20 43 68 72 28 31 30 30 20 2b 20 31 30 20 2b 20 35 29 20 2b 20 22 68 22 20 2b 20 22 65 6c 6c 22 } //1 = Chr(100 + 10 + 5) + "h" + "ell"
		$a_01_1 = {2e 43 6f 6e 74 72 6f 6c 73 28 31 29 2e 54 65 78 74 } //1 .Controls(1).Text
		$a_01_2 = {2e 43 6f 6e 74 72 6f 6c 73 28 30 20 2b 20 31 29 } //1 .Controls(0 + 1)
		$a_01_3 = {2e 56 61 6c 75 65 } //1 .Value
		$a_01_4 = {2e 4f 70 65 6e } //1 .Open
		$a_03_5 = {2e 57 72 69 74 65 4c 69 6e 65 20 90 02 18 2e 54 65 78 74 90 00 } //1
		$a_03_6 = {2e 43 72 65 61 74 65 54 65 78 74 46 69 6c 65 28 90 02 18 29 90 00 } //1
		$a_01_7 = {53 75 62 20 41 75 74 6f 4f 70 65 6e 28 29 } //1 Sub AutoOpen()
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_03_6  & 1)*1+(#a_01_7  & 1)*1) >=8
 
}