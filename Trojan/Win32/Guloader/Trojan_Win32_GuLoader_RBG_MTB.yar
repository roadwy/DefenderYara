
rule Trojan_Win32_GuLoader_RBG_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {69 6e 64 64 61 74 61 66 65 6c 74 } //1 inddatafelt
		$a_81_1 = {66 72 69 76 6f 6c 69 7a 65 64 20 75 6e 64 65 72 67 72 75 6e 64 73 6b 6f 6e 6f 6d 69 65 72 6e 65 73 } //1 frivolized undergrundskonomiernes
		$a_81_2 = {73 74 6f 72 65 62 72 6f 64 65 72 73 } //1 storebroders
		$a_81_3 = {6c 69 63 61 6e 73 20 76 6f 6c 64 65 6c 69 67 68 65 64 65 72 6e 65 2e 65 78 65 } //1 licans voldelighederne.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}