
rule _#PUA_Block_Findwide{
	meta:
		description = "!#PUA:Block:Findwide,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {4f 46 46 45 52 } //OFFER  1
		$a_80_1 = {43 43 6f 6d 54 6f 6f 6c 62 61 72 } //CComToolbar  1
		$a_80_2 = {53 45 54 5f 44 45 46 41 55 4c 54 5f 53 45 41 52 43 48 } //SET_DEFAULT_SEARCH  1
		$a_80_3 = {66 72 65 73 68 79 2e 63 6f 6d } //freshy.com  1
		$a_80_4 = {54 4e 54 32 55 73 65 72 2e 70 64 62 } //TNT2User.pdb  1
		$a_80_5 = {54 6f 6f 6c 62 61 72 49 6e 73 74 2e 65 78 65 } //ToolbarInst.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}
rule _#PUA_Block_Findwide_2{
	meta:
		description = "!#PUA:Block:Findwide,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {4f 46 46 45 52 } //OFFER  1
		$a_80_1 = {46 69 6e 64 77 69 64 65 } //Findwide  1
		$a_80_2 = {54 4e 54 32 55 73 65 72 50 53 36 34 2e 70 64 62 } //TNT2UserPS64.pdb  1
		$a_80_3 = {62 72 6f 77 73 65 72 53 65 61 72 63 68 53 65 72 76 69 63 65 } //browserSearchService  1
		$a_80_4 = {43 54 6f 6f 6c 62 61 72 44 6f 63 } //CToolbarDoc  1
		$a_80_5 = {54 4e 54 32 55 73 65 72 2e 65 78 65 } //TNT2User.exe  1
	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}