
rule Trojan_Win64_CryptInject_EZ_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.EZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 ff c6 44 30 e2 48 8b 85 ?? ?? ?? ?? 88 14 06 48 ff c0 49 89 d8 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}