
rule Trojan_Win64_CryptInject_YAH_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.YAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b9 11 00 00 00 99 f7 f9 8b 45 e0 48 63 d2 48 8d 0d ?? ?? ?? ?? 0f be 0c 11 31 c8 88 c2 48 8b 45 f0 48 63 4d e4 88 14 08 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}