
rule Trojan_Win32_OffLoader_SPLL_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.SPLL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_81_0 = {6e 75 6d 62 65 72 71 75 69 6e 63 65 2e 78 79 7a 2f 6c 69 2e 70 68 70 } //2 numberquince.xyz/li.php
	condition:
		((#a_81_0  & 1)*2) >=2
 
}
rule Trojan_Win32_OffLoader_SPLL_MTB_2{
	meta:
		description = "Trojan:Win32/OffLoader.SPLL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 00 6d 00 61 00 67 00 69 00 63 00 6c 00 75 00 6e 00 63 00 68 00 2e 00 69 00 63 00 75 00 2f 00 74 00 72 00 72 00 2e 00 70 00 68 00 70 00 } //2 /magiclunch.icu/trr.php
		$a_01_1 = {2f 00 73 00 69 00 6c 00 65 00 6e 00 74 00 } //1 /silent
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}