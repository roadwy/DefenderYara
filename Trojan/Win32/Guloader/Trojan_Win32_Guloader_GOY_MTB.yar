
rule Trojan_Win32_Guloader_GOY_MTB{
	meta:
		description = "Trojan:Win32/Guloader.GOY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_81_0 = {70 61 73 73 69 62 6c 65 20 6e 6f 6e 63 6f 6e 64 65 73 63 65 6e 64 69 6e 67 6e 65 73 73 20 63 6f 6e 67 61 65 72 6e 65 73 } //1 passible noncondescendingness congaernes
		$a_81_1 = {61 66 74 65 72 73 68 61 66 74 20 6f 72 61 63 75 6c 61 74 65 2e 65 78 65 } //1 aftershaft oraculate.exe
		$a_81_2 = {66 6f 72 74 6f 6c 6b 6e 69 6e 67 73 72 65 67 65 6c 65 6e 73 } //1 fortolkningsregelens
		$a_81_3 = {53 69 6c 69 6b 6f 6e 65 2e 74 72 6b } //1 Silikone.trk
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}