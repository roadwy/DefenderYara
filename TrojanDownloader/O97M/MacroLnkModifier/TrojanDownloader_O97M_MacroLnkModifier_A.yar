
rule TrojanDownloader_O97M_MacroLnkModifier_A{
	meta:
		description = "TrojanDownloader:O97M/MacroLnkModifier.A,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 07 00 00 "
		
	strings :
		$a_00_0 = {2e 63 72 65 61 74 65 6f 62 6a 65 63 74 28 } //1 .createobject(
		$a_00_1 = {2e 63 72 65 61 74 65 73 68 6f 72 74 63 75 74 28 } //1 .createshortcut(
		$a_00_2 = {2e 73 70 65 63 69 61 6c 66 6f 6c 64 65 72 73 28 61 63 74 69 76 65 73 68 65 65 74 2e 72 61 6e 67 65 } //1 .specialfolders(activesheet.range
		$a_00_3 = {2e 69 63 6f 6e 6c 6f 63 61 74 69 6f 6e 90 02 05 3d } //1
		$a_00_4 = {2e 61 72 67 75 6d 65 6e 74 73 90 02 05 3d } //1
		$a_00_5 = {2e 74 61 72 67 65 74 70 61 74 68 90 02 05 3d } //1
		$a_00_6 = {63 72 65 61 74 65 73 68 6f 72 74 63 75 74 28 90 02 10 73 70 65 63 69 61 6c 66 6f 6c 64 65 72 73 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=4
 
}