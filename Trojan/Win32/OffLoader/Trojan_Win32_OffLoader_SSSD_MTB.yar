
rule Trojan_Win32_OffLoader_SSSD_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.SSSD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {2f 00 73 00 6f 00 75 00 70 00 72 00 61 00 62 00 62 00 69 00 74 00 73 00 2e 00 78 00 79 00 7a 00 2f 00 6e 00 61 00 6f 00 2e 00 70 00 68 00 70 00 } //3 /souprabbits.xyz/nao.php
		$a_01_1 = {2f 00 73 00 69 00 6c 00 65 00 6e 00 74 00 } //1 /silent
	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}