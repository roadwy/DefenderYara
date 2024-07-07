
rule Trojan_Win32_Phorpiex_KA_MTB{
	meta:
		description = "Trojan:Win32/Phorpiex.KA!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {74 73 72 76 31 2e 77 73 } //1 tsrv1.ws
		$a_01_1 = {74 73 72 76 32 2e 74 6f 70 } //1 tsrv2.top
		$a_01_2 = {43 3a 5c 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 44 2e 70 64 62 } //1 C:\DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}