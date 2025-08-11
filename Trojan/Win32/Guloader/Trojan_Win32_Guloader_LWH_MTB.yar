
rule Trojan_Win32_Guloader_LWH_MTB{
	meta:
		description = "Trojan:Win32/Guloader.LWH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_81_0 = {66 6f 72 73 6b 65 72 67 72 75 70 70 65 73 2e 76 61 72 } //1 forskergruppes.var
		$a_81_1 = {6c 65 64 65 74 65 6b 73 74 65 72 73 2e 70 61 72 } //1 ledeteksters.par
		$a_81_2 = {73 70 6f 72 65 73 2e 73 61 76 } //1 spores.sav
		$a_81_3 = {55 6e 61 72 67 75 61 62 6c 65 2e 6f 63 65 } //1 Unarguable.oce
		$a_81_4 = {61 72 74 65 72 69 6f 6c 65 2e 66 6f 72 } //1 arteriole.for
		$a_81_5 = {73 6b 61 62 73 64 72 65 6e 65 73 20 66 69 6c 6f 73 } //1 skabsdrenes filos
		$a_81_6 = {68 69 6c 64 65 62 72 61 6e 64 73 2e 65 78 65 } //1 hildebrands.exe
		$a_81_7 = {73 65 6e 69 6c 69 74 65 74 65 6e } //1 seniliteten
		$a_81_8 = {73 69 62 65 20 70 68 79 6c 6c 6f 70 6f 64 69 75 6d 20 75 6c 74 72 61 73 74 72 69 63 74 } //1 sibe phyllopodium ultrastrict
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1+(#a_81_7  & 1)*1+(#a_81_8  & 1)*1) >=9
 
}