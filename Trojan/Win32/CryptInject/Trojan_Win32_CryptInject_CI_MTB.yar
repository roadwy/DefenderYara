
rule Trojan_Win32_CryptInject_CI_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.CI!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {39 ff 74 01 ea 31 07 42 81 c7 04 00 00 00 39 df 75 ee } //1
		$a_01_1 = {81 c1 01 00 00 00 81 eb 2b da 8f 9b 89 db 81 f9 7d db 00 01 75 a3 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}