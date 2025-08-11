
rule Trojan_Win32_GuLoader_RBC_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.RBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {5c 62 69 62 6c 69 6f 67 72 61 66 65 72 73 2e 74 6f 6c } //1 \bibliografers.tol
		$a_81_1 = {5c 46 6c 69 6d 70 31 33 37 } //1 \Flimp137
		$a_81_2 = {73 6b 62 6e 65 62 65 73 74 65 6d 74 65 20 63 6f 72 6f 64 69 61 72 79 } //1 skbnebestemte corodiary
		$a_81_3 = {6b 69 6b 6f 72 69 } //1 kikori
		$a_81_4 = {72 65 67 69 73 74 65 72 6e 61 76 6e 65 6e 65 73 } //1 registernavnenes
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}
rule Trojan_Win32_GuLoader_RBC_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.RBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {6c 65 76 6e 65 74 73 5c 73 65 6d 69 72 65 66 6c 65 78 69 76 65 6c 79 } //1 levnets\semireflexively
		$a_81_1 = {5c 44 65 73 65 72 74 69 6f 6e 65 72 5c 75 73 6b 69 6b 6b 65 6e 2e 67 69 66 } //1 \Desertioner\uskikken.gif
		$a_81_2 = {5c 61 61 6e 64 73 65 76 6e 65 72 5c 6e 61 74 72 69 63 69 6e 61 65 2e 69 6e 69 } //1 \aandsevner\natricinae.ini
		$a_81_3 = {6f 70 6b 72 76 65 64 65 73 20 67 72 61 66 69 6b 70 72 6f 67 72 61 6d 6d 65 72 20 61 6e 74 69 74 72 61 67 61 6c } //1 opkrvedes grafikprogrammer antitragal
		$a_81_4 = {6d 61 63 72 6f 73 79 6d 62 69 6f 6e 74 2e 65 78 65 } //1 macrosymbiont.exe
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}