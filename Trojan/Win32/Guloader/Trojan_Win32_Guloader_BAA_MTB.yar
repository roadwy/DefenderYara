
rule Trojan_Win32_Guloader_BAA_MTB{
	meta:
		description = "Trojan:Win32/Guloader.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {50 85 d2 85 db 5b 66 85 d2 66 3d ?? ?? 01 d3 66 85 c0 66 85 c0 31 0b e9 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win32_Guloader_BAA_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.BAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_81_0 = {46 72 65 6b 76 65 6e 74 65 72 65 6e 64 65 40 53 74 65 6e 63 69 6c 73 2e 75 6e 61 31 } //1 Frekventerende@Stencils.una1
		$a_81_1 = {54 61 6e 64 73 6b 69 76 65 31 } //1 Tandskive1
		$a_81_2 = {43 6c 6f 6d 62 20 55 68 72 74 65 73 20 53 70 72 65 61 64 61 74 69 6f 6e } //1 Clomb Uhrtes Spreadation
		$a_81_3 = {54 61 6e 64 73 6b 69 76 65 } //1 Tandskive
		$a_81_4 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e } //1 Software\Microsoft\Windows\CurrentVersion
		$a_81_5 = {66 69 62 72 69 6e 6f 6c 79 73 69 73 20 69 6e 64 69 73 63 72 65 74 65 20 69 73 69 6e 64 61 7a 6f 6c 65 } //1 fibrinolysis indiscrete isindazole
		$a_81_6 = {73 79 7a 65 74 74 20 64 61 6d 61 6e 73 } //1 syzett damans
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1+(#a_81_6  & 1)*1) >=7
 
}