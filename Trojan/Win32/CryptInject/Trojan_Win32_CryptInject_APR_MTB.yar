
rule Trojan_Win32_CryptInject_APR_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.APR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {68 00 a3 e1 11 6a 01 ff 15 ?? 00 01 10 } //1
		$a_03_1 = {01 10 0f b6 05 ?? ?? 01 10 c1 f8 06 0f b6 0d ?? ?? 01 10 c1 e1 02 0b c1 a2 ?? ?? 01 10 0f b6 ?? ?? ?? 01 10 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}