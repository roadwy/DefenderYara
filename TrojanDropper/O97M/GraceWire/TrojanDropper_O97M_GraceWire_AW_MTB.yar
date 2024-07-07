
rule TrojanDropper_O97M_GraceWire_AW_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.AW!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 65 78 74 42 6f 78 31 54 61 67 20 3d 20 55 73 65 72 46 6f 72 6d 32 2e 54 65 78 74 42 6f 78 31 2e 54 61 67 } //1 TextBox1Tag = UserForm2.TextBox1.Tag
		$a_01_1 = {5a 69 70 4e 61 6d 65 20 3d 20 54 65 78 74 42 6f 78 31 54 61 67 20 2b 20 22 2e 7a 69 70 22 } //1 ZipName = TextBox1Tag + ".zip"
		$a_01_2 = {50 75 74 20 23 31 2c 20 2c 20 54 65 6d 70 5a 65 72 6f } //1 Put #1, , TempZero
		$a_01_3 = {6f 41 70 70 2e 4e 61 6d 65 73 70 61 63 65 28 5a 69 70 46 6f 6c 64 65 72 29 2e 43 6f 70 79 48 65 72 65 20 6f 62 6a 46 6f 6c 64 65 72 2e 69 74 65 6d 73 2e 49 74 65 6d } //1 oApp.Namespace(ZipFolder).CopyHere objFolder.items.Item
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}