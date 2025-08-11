
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
rule Trojan_Win32_GuLoader_RBG_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.RBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {4b 6e 69 67 68 74 2d 52 69 64 64 65 72 20 49 6e 63 2e } //1 Knight-Ridder Inc.
		$a_81_1 = {56 69 61 64 20 43 6f 72 70 } //1 Viad Corp
		$a_81_2 = {4d 65 64 74 72 6f 6e 69 63 20 49 6e 63 2e } //1 Medtronic Inc.
		$a_81_3 = {43 6f 6d 66 6f 72 74 20 53 79 73 74 65 6d 73 20 55 53 41 20 49 6e 63 2e } //1 Comfort Systems USA Inc.
		$a_81_4 = {75 6e 72 65 77 6f 72 64 65 64 20 64 65 6d 69 6d 6f 6e 64 6e 2e 65 78 65 } //1 unreworded demimondn.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}