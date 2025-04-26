
rule Trojan_Win32_OffLoader_SCVC_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.SCVC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 00 61 00 74 00 74 00 72 00 61 00 63 00 74 00 69 00 6f 00 6e 00 6b 00 6e 00 6f 00 77 00 6c 00 65 00 64 00 67 00 65 00 2e 00 73 00 62 00 73 00 2f 00 73 00 6e 00 79 00 2e 00 70 00 68 00 70 00 } //3 /attractionknowledge.sbs/sny.php
		$a_01_1 = {2f 00 73 00 69 00 6c 00 65 00 6e 00 74 00 } //2 /silent
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}