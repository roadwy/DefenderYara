
rule Trojan_Win32_Delf_AF_MTB{
	meta:
		description = "Trojan:Win32/Delf.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1b 00 1b 00 09 00 00 "
		
	strings :
		$a_80_0 = {47 6c 79 70 68 2e 44 61 74 61 } //Glyph.Data  3
		$a_80_1 = {6c 61 57 65 62 53 69 74 65 41 64 64 72 65 73 73 43 6c 69 63 6b } //laWebSiteAddressClick  3
		$a_80_2 = {6c 61 57 65 62 53 69 74 65 41 64 64 72 65 73 73 4d 6f 75 73 65 45 6e 74 65 72 } //laWebSiteAddressMouseEnter  3
		$a_80_3 = {6c 61 57 65 62 53 69 74 65 41 64 64 72 65 73 73 4d 6f 75 73 65 4c 65 61 76 65 } //laWebSiteAddressMouseLeave  3
		$a_80_4 = {53 74 75 64 4d 61 69 6c 65 72 } //StudMailer  3
		$a_80_5 = {41 64 6a 75 73 74 57 69 6e 64 6f 77 52 65 63 74 45 78 } //AdjustWindowRectEx  3
		$a_80_6 = {41 63 74 69 76 61 74 65 4b 65 79 62 6f 61 72 64 4c 61 79 6f 75 74 } //ActivateKeyboardLayout  3
		$a_80_7 = {47 65 74 4b 65 79 62 6f 61 72 64 53 74 61 74 65 } //GetKeyboardState  3
		$a_80_8 = {47 65 74 4b 65 79 62 6f 61 72 64 4c 61 79 6f 75 74 } //GetKeyboardLayout  3
	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3+(#a_80_6  & 1)*3+(#a_80_7  & 1)*3+(#a_80_8  & 1)*3) >=27
 
}