
rule Trojan_Win32_RedLine_MBII_MTB{
	meta:
		description = "Trojan:Win32/RedLine.MBII!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {73 61 76 75 6a 6f 72 61 74 65 62 6f 6c 69 7a 69 6c 61 62 65 7a 6f 68 6f 79 69 63 75 6b 6f 6d 6f 20 78 69 6c 69 77 75 74 } //1 savujoratebolizilabezohoyicukomo xiliwut
		$a_81_1 = {54 61 67 20 76 75 6b 75 7a 6f 6c 6f 74 69 74 65 6b 65 7a } //1 Tag vukuzolotitekez
		$a_81_2 = {74 75 70 69 70 65 76 69 6a 61 79 69 67 69 78 69 66 75 } //1 tupipevijayigixifu
		$a_81_3 = {76 69 6c 6f 6b 65 6d 61 62 65 7a 6f 6d 61 77 69 66 6f } //1 vilokemabezomawifo
		$a_81_4 = {63 69 63 6f 6b 69 72 61 66 69 6e 69 62 69 72 6f 7a 61 74 75 77 61 6a } //1 cicokirafinibirozatuwaj
	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}