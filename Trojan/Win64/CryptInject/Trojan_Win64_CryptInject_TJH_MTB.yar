
rule Trojan_Win64_CryptInject_TJH_MTB{
	meta:
		description = "Trojan:Win64/CryptInject.TJH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 8b 8a 84 00 00 00 45 8b c1 44 0f af c2 45 2b c1 ff ca 49 63 c8 48 03 0d 96 00 03 00 0f b7 01 66 41 33 c3 66 85 c3 74 06 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}