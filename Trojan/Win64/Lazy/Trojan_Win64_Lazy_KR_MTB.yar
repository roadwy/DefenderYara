
rule Trojan_Win64_Lazy_KR_MTB{
	meta:
		description = "Trojan:Win64/Lazy.KR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {65 48 8b 04 25 60 00 00 00 33 ff 8b d9 48 85 c0 74 6e 4c 8b 40 18 4d 85 c0 74 65 49 83 c0 10 49 8b 10 eb 57 4c 8b 4a 60 4d 85 c9 74 4b 66 39 7a 58 76 45 44 0f b7 52 58 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}