
rule Trojan_Win32_OffLoader_AVJA_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.AVJA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 05 00 00 "
		
	strings :
		$a_80_0 = {3a 2f 2f 73 68 61 6d 65 73 65 72 76 61 6e 74 2e 69 63 75 2f 6c 6b 6f 2e 70 68 70 3f } //://shameservant.icu/lko.php?  4
		$a_80_1 = {2f 73 69 6c 65 6e 74 } ///silent  1
		$a_80_2 = {2f 77 65 61 6b 73 65 63 75 72 69 74 79 } ///weaksecurity  1
		$a_80_3 = {2f 6e 6f 63 6f 6f 6b 69 65 73 } ///nocookies  1
		$a_80_4 = {2f 72 65 73 75 6d 65 } ///resume  1
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1) >=8
 
}