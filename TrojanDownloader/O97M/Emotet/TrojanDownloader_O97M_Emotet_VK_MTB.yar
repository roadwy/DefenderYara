
rule TrojanDownloader_O97M_Emotet_VK_MTB{
	meta:
		description = "TrojanDownloader:O97M/Emotet.VK!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {43 61 6c 6c 20 90 02 20 2e 20 5f 90 0c 02 00 43 72 65 61 74 65 28 90 02 20 2c 20 90 05 0f 06 41 2d 5a 61 2d 7a 2c 90 00 } //1
		$a_03_1 = {3d 20 4a 6f 69 6e 28 53 70 6c 69 74 28 90 02 40 2c 20 90 02 40 29 2c 20 22 22 20 90 02 10 29 90 00 } //1
		$a_01_2 = {2e 43 6f 6e 74 72 6f 6c 54 69 70 54 65 78 74 20 2b 20 22 2d 65 20 22 } //1 .ControlTipText + "-e "
		$a_01_3 = {44 65 62 75 67 2e 50 72 69 6e 74 20 22 4f 70 65 72 61 69 6f 6e 22 20 2b 20 4e 53 20 2b 20 22 53 22 } //1 Debug.Print "Operaion" + NS + "S"
		$a_01_4 = {53 74 72 52 65 76 65 72 73 65 28 64 73 65 29 } //1 StrReverse(dse)
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}