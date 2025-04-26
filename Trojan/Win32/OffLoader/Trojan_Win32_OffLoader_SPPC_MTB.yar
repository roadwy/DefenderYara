
rule Trojan_Win32_OffLoader_SPPC_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.SPPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 00 68 00 6f 00 72 00 6e 00 71 00 75 00 69 00 76 00 65 00 72 00 2e 00 69 00 63 00 75 00 2f 00 6b 00 6f 00 6e 00 64 00 2e 00 70 00 68 00 70 00 } //3 /hornquiver.icu/kond.php
		$a_01_1 = {2f 00 70 00 69 00 7a 00 7a 00 61 00 73 00 72 00 65 00 61 00 73 00 6f 00 6e 00 2e 00 69 00 63 00 75 00 2f 00 6b 00 75 00 6e 00 64 00 2e 00 70 00 68 00 70 00 } //3 /pizzasreason.icu/kund.php
		$a_01_2 = {2f 00 73 00 69 00 6c 00 65 00 6e 00 74 00 } //1 /silent
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1) >=7
 
}