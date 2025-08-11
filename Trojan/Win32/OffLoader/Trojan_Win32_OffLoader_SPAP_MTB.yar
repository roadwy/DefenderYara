
rule Trojan_Win32_OffLoader_SPAP_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.SPAP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {73 00 70 00 6f 00 6f 00 6e 00 70 00 6f 00 72 00 74 00 65 00 72 00 2e 00 78 00 79 00 7a 00 2f 00 6b 00 69 00 79 00 73 00 2e 00 70 00 68 00 70 00 } //4 spoonporter.xyz/kiys.php
		$a_01_1 = {2f 00 73 00 69 00 6c 00 65 00 6e 00 74 00 } //1 /silent
	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1) >=5
 
}