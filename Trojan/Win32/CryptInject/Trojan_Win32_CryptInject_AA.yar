
rule Trojan_Win32_CryptInject_AA{
	meta:
		description = "Trojan:Win32/CryptInject.AA,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {01 00 00 c6 05 ?? ?? 40 00 6e c6 05 ?? ?? 40 00 74 8d 35 ?? ?? 40 00 56 } //1
		$a_02_1 = {8b 07 f8 83 d7 04 f7 ?? 83 c0 da f8 83 d0 ff 29 c8 6a ff 59 21 c1 89 02 83 c2 04 f8 83 de 04 85 f6 75 dd } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}