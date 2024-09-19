
rule Trojan_Win32_CryptInject_MBFH_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.MBFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {21 40 00 a4 12 40 00 00 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 00 00 00 00 e9 00 00 00 0c 11 40 00 0c 11 40 00 d0 10 40 00 78 } //1
		$a_01_1 = {80 00 00 00 83 00 00 00 84 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 6b 77 73 69 71 67 67 00 55 5a 00 00 55 5a } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}