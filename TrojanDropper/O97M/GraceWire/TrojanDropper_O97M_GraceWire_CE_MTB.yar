
rule TrojanDropper_O97M_GraceWire_CE_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.CE!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {2b 20 22 2e 64 6c 6c 22 } //1 + ".dll"
		$a_03_1 = {43 61 73 65 20 32 [0-12] 73 20 3d 20 22 4d 61 6a 6f 72 20 68 65 61 6c 74 68 20 70 72 6f 62 6c 65 6d 73 22 } //1
		$a_03_2 = {4e 65 78 74 20 6b [0-04] 45 78 69 74 20 44 6f [0-04] 45 6c 73 65 [0-04] 63 75 72 } //1
		$a_03_3 = {2e 54 65 78 74 42 6f 78 31 2e 54 61 67 [0-08] 44 69 6d } //1
		$a_01_4 = {74 65 78 74 49 74 65 6d 20 3d 20 57 69 6e 64 6f 77 73 2e 4c 61 62 65 6c 31 31 2e 43 61 70 74 69 6f 6e } //1 textItem = Windows.Label11.Caption
		$a_01_5 = {43 68 44 69 72 20 57 69 6e 64 6f 77 73 2e 54 65 78 74 42 6f 78 33 2e 54 61 67 } //1 ChDir Windows.TextBox3.Tag
		$a_01_6 = {3d 20 73 4e 4d 53 50 2e 4e 61 6d 65 73 70 61 63 65 28 64 65 72 73 68 6c 65 70 29 } //1 = sNMSP.Namespace(dershlep)
	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=7
 
}