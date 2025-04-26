
rule Trojan_Win32_CryptInject_MBHW_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.MBHW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {fe 35 00 00 0e 36 00 00 22 36 00 00 34 36 00 00 46 36 } //1
		$a_01_1 = {1c 18 40 00 00 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 01 00 00 00 e9 00 00 00 f4 14 40 00 74 14 40 00 9c 13 40 00 78 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}