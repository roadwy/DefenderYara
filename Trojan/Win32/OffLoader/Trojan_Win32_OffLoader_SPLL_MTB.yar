
rule Trojan_Win32_OffLoader_SPLL_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.SPLL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_81_0 = {6e 75 6d 62 65 72 71 75 69 6e 63 65 2e 78 79 7a 2f 6c 69 2e 70 68 70 } //2 numberquince.xyz/li.php
	condition:
		((#a_81_0  & 1)*2) >=2
 
}