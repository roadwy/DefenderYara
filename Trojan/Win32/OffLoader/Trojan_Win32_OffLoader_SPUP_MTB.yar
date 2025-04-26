
rule Trojan_Win32_OffLoader_SPUP_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.SPUP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {62 00 6c 00 6f 00 77 00 72 00 61 00 69 00 6e 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 6e 00 6a 00 67 00 2e 00 70 00 68 00 70 00 } //2 blowrain.website/njg.php
		$a_01_1 = {65 00 6e 00 67 00 69 00 6e 00 65 00 77 00 69 00 6e 00 65 00 2e 00 78 00 79 00 7a 00 2f 00 6e 00 6a 00 6b 00 2e 00 70 00 68 00 70 00 } //2 enginewine.xyz/njk.php
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}