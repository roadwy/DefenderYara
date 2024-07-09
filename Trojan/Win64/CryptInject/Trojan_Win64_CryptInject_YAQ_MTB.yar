
rule Trojan_Win64_CryptInject_YAQ_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.YAQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 d0 48 c1 e0 03 48 01 d0 48 01 c0 48 29 c1 48 89 ca 8b 85 ?? ?? ?? ?? 48 98 48 01 d0 0f b6 84 05 ?? ?? ?? ?? 44 31 c8 41 88 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}