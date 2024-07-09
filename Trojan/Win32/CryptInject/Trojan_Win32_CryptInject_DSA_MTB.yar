
rule Trojan_Win32_CryptInject_DSA_MTB{
	meta:
		description = "Trojan:Win32/CryptInject.DSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c0 8b c0 eb ?? 33 05 ?? ?? ?? ?? 8b c0 8b c0 } //1
		$a_02_1 = {8b c0 8b c8 8b d1 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 89 08 5f 5d c3 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}