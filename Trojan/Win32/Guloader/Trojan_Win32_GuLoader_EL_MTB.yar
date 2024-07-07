
rule Trojan_Win32_GuLoader_EL_MTB{
	meta:
		description = "Trojan:Win32/GuLoader.EL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {53 6c 69 70 70 65 73 32 2e 6c 6e 6b } //1 Slippes2.lnk
		$a_01_1 = {42 00 72 00 6f 00 6e 00 63 00 68 00 75 00 73 00 } //1 Bronchus
		$a_01_2 = {50 00 72 00 69 00 6e 00 74 00 48 00 6f 00 6f 00 64 00 5c 00 42 00 72 00 79 00 6f 00 6c 00 6f 00 67 00 69 00 5c 00 2a 00 2e 00 54 00 65 00 72 00 } //1 PrintHood\Bryologi\*.Ter
		$a_01_3 = {4f 70 64 61 74 65 72 69 6e 67 73 73 69 64 65 72 6e 65 31 36 36 } //1 Opdateringssiderne166
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}
rule Trojan_Win32_GuLoader_EL_MTB_2{
	meta:
		description = "Trojan:Win32/GuLoader.EL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4c 6e 6b 6f 6e 74 6f 73 2e 44 65 77 } //1 Lnkontos.Dew
		$a_01_1 = {74 68 69 72 64 6e 65 73 73 5c 54 72 61 6e 73 70 68 79 73 69 63 61 6c 5c 62 75 72 68 6e 65 2e 64 6c 6c } //1 thirdness\Transphysical\burhne.dll
		$a_01_2 = {42 00 72 00 75 00 67 00 65 00 72 00 6f 00 72 00 64 00 62 00 6f 00 67 00 5c 00 2a 00 2e 00 6b 00 6c 00 74 00 } //1 Brugerordbog\*.klt
		$a_01_3 = {54 00 65 00 61 00 6d 00 77 00 6f 00 72 00 6b 00 65 00 74 00 33 00 32 00 } //1 Teamworket32
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}