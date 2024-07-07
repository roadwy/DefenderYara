
rule Trojan_Win32_NSISInject_FR_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.FR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {53 6f 66 74 77 61 72 65 5c 53 74 61 74 73 72 65 74 74 65 6e } //1 Software\Statsretten
		$a_81_1 = {43 6f 6d 70 61 72 61 74 65 2e 43 68 75 31 35 33 } //1 Comparate.Chu153
		$a_81_2 = {53 6f 66 74 77 61 72 65 5c 77 65 74 6e 65 73 73 5c 4b 6e 75 73 65 6c 73 6b 65 73 } //1 Software\wetness\Knuselskes
		$a_81_3 = {53 79 67 65 66 6f 72 73 69 6b 72 69 6e 67 73 } //1 Sygeforsikrings
		$a_81_4 = {53 6f 66 74 77 61 72 65 5c 54 61 6c 62 6c 6f 6b 6b 65 6e 5c 70 72 65 74 74 69 65 73 74 } //1 Software\Talblokken\prettiest
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}