
rule Trojan_Win32_GuLoader_RBJ_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {53 69 6c 69 63 69 75 6d 65 74 73 5c 74 72 79 6b 6b 65 74 65 6b 6e 69 6b 6b 65 72 6e 65 5c 6c 69 76 73 66 6f 72 73 69 6b 72 69 6e 67 65 6e 73 } //1 Siliciumets\trykketeknikkerne\livsforsikringens
		$a_81_1 = {25 50 73 65 75 64 6f 61 6e 61 74 6f 6d 69 63 25 5c 4b 72 6f 63 6b 65 74 32 32 } //1 %Pseudoanatomic%\Krocket22
		$a_81_2 = {35 5c 53 6e 6f 72 6b 65 6c 2e 45 76 65 } //1 5\Snorkel.Eve
		$a_81_3 = {6d 65 6c 6c 65 6d 67 61 6e 67 65 6e 65 20 6d 6f 65 72 6b 65 74 20 72 65 73 69 74 75 61 74 65 73 } //1 mellemgangene moerket resituates
		$a_81_4 = {76 69 73 69 74 61 74 69 6f 6e 20 62 61 67 67 61 67 65 73 } //1 visitation baggages
		$a_81_5 = {73 65 6d 69 63 6f 6c 6c 65 67 69 61 74 65 2e 65 78 65 } //1 semicollegiate.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}