
rule Trojan_Win32_OffLoader_SPBC_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.SPBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 00 63 00 68 00 69 00 6e 00 74 00 72 00 61 00 79 00 2e 00 77 00 65 00 62 00 73 00 69 00 74 00 65 00 2f 00 6f 00 75 00 74 00 6f 00 2e 00 70 00 68 00 70 00 } //5 /chintray.website/outo.php
		$a_01_1 = {2f 00 73 00 69 00 6c 00 65 00 6e 00 74 00 } //1 /silent
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}