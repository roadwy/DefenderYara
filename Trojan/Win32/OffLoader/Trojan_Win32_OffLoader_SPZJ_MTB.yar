
rule Trojan_Win32_OffLoader_SPZJ_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.SPZJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 00 63 00 72 00 69 00 6d 00 65 00 61 00 75 00 74 00 68 00 6f 00 72 00 69 00 74 00 79 00 2e 00 63 00 66 00 64 00 2f 00 74 00 69 00 75 00 2e 00 70 00 68 00 70 00 } //3 /crimeauthority.cfd/tiu.php
		$a_01_1 = {2f 00 73 00 69 00 6c 00 65 00 6e 00 74 00 } //1 /silent
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}