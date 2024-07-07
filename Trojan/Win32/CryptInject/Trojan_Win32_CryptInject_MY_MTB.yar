
rule Trojan_Win32_CryptInject_MY_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.MY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {64 a1 30 00 00 00 8b 40 0c 57 31 ef 47 56 } //1
		$a_01_1 = {70 6f 77 72 70 72 6f 66 2e 70 64 62 } //1 powrprof.pdb
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}