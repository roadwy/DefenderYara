
rule Trojan_Win32_OffLoader_SPAC_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.SPAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 00 2f 00 7a 00 69 00 70 00 70 00 65 00 72 00 77 00 6f 00 72 00 6b 00 2e 00 69 00 63 00 75 00 2f 00 72 00 69 00 64 00 2e 00 70 00 68 00 70 00 } //4 //zipperwork.icu/rid.php
		$a_01_1 = {2f 00 73 00 69 00 6c 00 65 00 6e 00 74 00 } //1 /silent
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}