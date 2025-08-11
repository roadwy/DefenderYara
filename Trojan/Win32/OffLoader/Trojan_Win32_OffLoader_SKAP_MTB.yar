
rule Trojan_Win32_OffLoader_SKAP_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.SKAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_80_0 = {61 69 72 70 6f 72 74 69 63 69 63 6c 65 2e 69 6e 66 6f 2f 78 63 78 2e 70 68 70 } //airporticicle.info/xcx.php  4
		$a_80_1 = {2f 73 69 6c 65 6e 74 } ///silent  1
		$a_80_2 = {2f 77 65 61 6b 73 65 63 75 72 69 74 79 } ///weaksecurity  1
		$a_80_3 = {2f 6e 6f 63 6f 6f 6b 69 65 73 } ///nocookies  1
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=7
 
}