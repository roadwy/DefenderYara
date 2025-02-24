
rule Trojan_Win32_OffLoader_SPOC_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.SPOC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 00 72 00 65 00 71 00 75 00 65 00 73 00 74 00 61 00 6e 00 74 00 73 00 2e 00 73 00 62 00 73 00 2f 00 64 00 65 00 63 00 2e 00 70 00 68 00 70 00 } //3 /requestants.sbs/dec.php
		$a_01_1 = {2f 00 73 00 69 00 6c 00 65 00 6e 00 74 00 } //2 /silent
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}