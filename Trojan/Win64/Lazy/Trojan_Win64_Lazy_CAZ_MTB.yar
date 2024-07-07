
rule Trojan_Win64_Lazy_CAZ_MTB{
	meta:
		description = "Trojan:Win64/Lazy.CAZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 18 48 63 4c 24 14 0f be 14 08 48 8b 44 24 28 44 8b 44 24 14 48 89 44 24 08 44 89 c0 89 54 24 04 99 41 b8 90 01 04 41 f7 f8 48 63 ca 8b 54 24 04 4c 8b 4c 24 08 41 33 14 89 41 88 d2 48 8b 4c 24 18 4c 63 5c 24 14 46 88 14 19 8b 44 24 14 83 c0 90 01 01 89 44 24 14 e9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}