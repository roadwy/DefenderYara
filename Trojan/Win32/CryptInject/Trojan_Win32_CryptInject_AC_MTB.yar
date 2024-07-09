
rule Trojan_Win32_CryptInject_AC_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {31 cb 59 f7 db f7 d3 81 c3 [0-04] 29 d8 5b ff 20 } //1
		$a_03_1 = {89 e9 81 c1 [0-04] 2b 31 89 e9 81 c1 [0-04] 31 31 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}