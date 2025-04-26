
rule TrojanDropper_O97M_GraceWire_BH_MTB{
	meta:
		description = "TrojanDropper:O97M/GraceWire.BH!MTB,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {43 6f 6d 70 6f 73 69 74 69 6f 6e 20 [0-15] 20 26 20 55 73 65 72 46 6f 72 6d 36 2e 4c 61 62 65 6c 31 2e 54 61 67 2c 20 6f 66 62 6c 2c 20 43 75 72 72 65 6e 74 53 69 7a 65 4f 66 41 54 2c 20 73 65 6e 64 69 6e 67 73 } //1
		$a_01_1 = {46 69 6c 65 57 68 65 72 65 50 75 74 54 6f 32 2e 43 6f 70 79 48 65 72 65 20 46 69 6c 65 57 68 65 72 65 50 75 74 54 6f 2e 49 74 65 6d 73 2e 49 74 65 6d 28 55 73 65 72 46 6f 72 6d 36 2e 4c 61 62 65 6c 31 31 2e 54 61 67 29 } //1 FileWherePutTo2.CopyHere FileWherePutTo.Items.Item(UserForm6.Label11.Tag)
		$a_01_2 = {63 74 61 63 6b 50 69 70 20 3d 20 4a 6f 69 6e 28 66 6f 6f 6f 42 61 72 2c 20 22 22 29 } //1 ctackPip = Join(foooBar, "")
		$a_03_3 = {44 6f 45 76 65 6e 74 73 90 0c 02 00 44 65 72 54 69 70 90 0c 02 00 44 6f 45 76 65 6e 74 73 90 0c 02 00 45 6e 64 20 53 75 62 } //1
		$a_01_4 = {74 74 20 3d 20 74 74 20 26 20 73 54 28 69 69 29 20 26 20 22 5c 22 } //1 tt = tt & sT(ii) & "\"
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}