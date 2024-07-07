
rule Trojan_Win32_Guloader_CP_MTB{
	meta:
		description = "Trojan:Win32/Guloader.CP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_81_0 = {42 75 74 69 6b 73 74 69 64 65 6e 73 31 35 30 5c 68 65 6c 75 6c 64 65 6e 74 5c 72 65 74 72 74 65 6e 73 } //1 Butikstidens150\heluldent\retrtens
		$a_81_1 = {53 6f 66 74 77 61 72 65 5c 73 6b 69 72 74 69 6e 67 6c 79 5c 6b 6c 6f 61 6b 6b 65 6e } //1 Software\skirtingly\kloakken
		$a_81_2 = {70 72 6f 64 75 6b 74 65 76 61 6c 75 65 72 69 6e 67 65 72 73 5c 66 61 72 62 61 72 65 73 2e 64 6c 6c } //1 produktevalueringers\farbares.dll
		$a_81_3 = {75 6e 68 61 73 68 65 64 2e 74 78 74 } //1 unhashed.txt
		$a_81_4 = {76 61 6e 64 79 6b 65 64 5c 55 64 6c 69 67 67 65 72 62 61 61 64 65 2e 62 65 6c } //1 vandyked\Udliggerbaade.bel
		$a_81_5 = {53 75 62 70 72 65 63 65 70 74 6f 72 61 6c 2e 74 61 67 } //1 Subpreceptoral.tag
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1+(#a_81_5  & 1)*1) >=6
 
}