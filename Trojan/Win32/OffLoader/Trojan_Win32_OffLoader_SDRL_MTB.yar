
rule Trojan_Win32_OffLoader_SDRL_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.SDRL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 00 63 00 68 00 65 00 72 00 72 00 79 00 66 00 6f 00 72 00 63 00 65 00 2e 00 78 00 79 00 7a 00 2f 00 67 00 6f 00 74 00 61 00 2e 00 70 00 68 00 70 00 } //2 /cherryforce.xyz/gota.php
		$a_01_1 = {2f 00 73 00 69 00 6c 00 65 00 6e 00 74 00 } //1 /silent
	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}