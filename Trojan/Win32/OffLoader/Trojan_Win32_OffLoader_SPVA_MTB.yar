
rule Trojan_Win32_OffLoader_SPVA_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.SPVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_81_0 = {2f 2f 68 6f 74 66 72 69 63 74 69 6f 6e 2e 78 79 7a 2f 6c 6b 6f 6f 2e 70 68 70 } //4 //hotfriction.xyz/lkoo.php
		$a_81_1 = {2f 73 69 6c 65 6e 74 } //1 /silent
	condition:
		((#a_81_0  & 1)*4+(#a_81_1  & 1)*1) >=5
 
}