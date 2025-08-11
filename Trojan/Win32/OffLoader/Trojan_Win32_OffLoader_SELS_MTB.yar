
rule Trojan_Win32_OffLoader_SELS_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.SELS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_80_0 = {2f 2f 77 69 73 68 73 6f 6e 2e 69 63 75 2f 69 64 6f 2e 70 68 70 } ////wishson.icu/ido.php  4
		$a_80_1 = {2f 73 69 6c 65 6e 74 } ///silent  1
		$a_80_2 = {2f 77 65 61 6b 73 65 63 75 72 69 74 79 } ///weaksecurity  1
	condition:
		((#a_80_0  & 1)*4+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=6
 
}