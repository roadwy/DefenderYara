
rule TrojanDownloader_O97M_Obfuse_OE_MTB{
	meta:
		description = "TrojanDownloader:O97M/Obfuse.OE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {48 79 70 65 72 58 20 3d 20 48 79 70 65 72 58 20 2b 20 30 2e } //1 HyperX = HyperX + 0.
		$a_01_1 = {53 65 6c 65 63 74 69 6f 6e 2e 54 79 70 65 54 65 78 74 20 54 65 78 74 3a 3d 22 } //1 Selection.TypeText Text:="
		$a_03_2 = {22 63 3a 5c 90 02 20 2e 62 61 74 22 2c 20 54 72 75 65 90 00 } //1
		$a_01_3 = {2a 20 46 69 78 28 } //1 * Fix(
		$a_01_4 = {2a 20 4c 69 74 65 29 } //1 * Lite)
		$a_01_5 = {26 20 22 7c 22 20 26 20 42 20 26 20 22 7c 22 20 26 } //1 & "|" & B & "|" &
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}