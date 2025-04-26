
rule Trojan_O97M_Donoff{
	meta:
		description = "Trojan:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_00_0 = {4b 6f 70 68 79 5f 50 61 69 6e 74 65 64 } //1 Kophy_Painted
		$a_00_1 = {2e 53 65 74 52 65 71 75 65 73 74 48 65 61 64 65 72 } //1 .SetRequestHeader
		$a_00_2 = {2e 4f 70 65 6e } //1 .Open
		$a_00_3 = {2e 53 65 6e 64 } //1 .Send
		$a_00_4 = {2e 52 65 73 70 6f 6e 73 65 54 65 78 74 } //1 .ResponseText
		$a_00_5 = {2c 20 32 39 2c 20 35 35 29 2c 20 5f } //1 , 29, 55), _
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=6
 
}
rule Trojan_O97M_Donoff_2{
	meta:
		description = "Trojan:O97M/Donoff,SIGNATURE_TYPE_MACROHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_00_0 = {45 6e 75 6d 53 79 73 74 65 6d 4c 61 6e 67 75 61 67 65 47 72 6f 75 70 73 41 } //1 EnumSystemLanguageGroupsA
		$a_00_1 = {54 68 69 73 44 6f 63 75 6d 65 6e 74 2e 50 61 74 68 } //1 ThisDocument.Path
		$a_00_2 = {41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 42 6f 6f 6b 6d 61 72 6b 73 2e 43 6f 75 6e 74 } //1 ActiveDocument.Bookmarks.Count
		$a_00_3 = {65 6e 74 65 72 70 72 69 73 65 20 3d 20 62 6f 78 6c 69 6b 65 20 2d 20 31 39 35 } //1 enterprise = boxlike - 195
		$a_00_4 = {66 72 61 6e 63 6f 70 68 6f 62 65 20 3d 20 70 68 65 6c 6c 6f 64 65 6e 64 72 6f 6e 28 70 72 6f 6c 6f 67 29 } //1 francophobe = phellodendron(prolog)
		$a_00_5 = {63 6c 6f 67 28 61 64 65 65 6d 20 2b 20 61 77 61 72 65 29 } //1 clog(adeem + aware)
		$a_00_6 = {49 66 20 74 61 62 6c 65 63 6c 6f 74 68 20 2b 20 61 63 65 74 61 6d 69 6e 6f 70 68 65 6e } //1 If tablecloth + acetaminophen
	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1+(#a_00_6  & 1)*1) >=5
 
}