
rule Trojan_Win32_AveMaria_NA_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.NA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 09 00 00 "
		
	strings :
		$a_01_0 = {4d 41 4c 49 4e 41 47 45 52 42 49 54 41 4c 41 53 4f 4d 45 44 41 4b 4f 4e 49 52 41 4d 49 43 52 41 50 43 } //1 MALINAGERBITALASOMEDAKONIRAMICRAPC
		$a_01_1 = {41 4d 50 4f 53 43 4f 4c 41 } //1 AMPOSCOLA
		$a_01_2 = {43 45 44 52 45 4b 41 53 4d 50 53 } //1 CEDREKASMPS
		$a_01_3 = {54 48 45 42 53 46 4f 55 52 } //1 THEBSFOUR
		$a_01_4 = {57 45 43 48 41 4e 47 45 4d 4f 53 41 57 41 53 44 4d 4d } //1 WECHANGEMOSAWASDMM
		$a_01_5 = {49 45 4e 55 53 4f 4e 45 } //1 IENUSONE
		$a_01_6 = {55 54 4d 41 47 4f 53 49 54 } //1 UTMAGOSIT
		$a_01_7 = {79 54 48 45 43 4f } //1 yTHECO
		$a_01_8 = {58 48 53 48 4f 54 50 53 } //1 XHSHOTPS
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1+(#a_01_8  & 1)*1) >=9
 
}