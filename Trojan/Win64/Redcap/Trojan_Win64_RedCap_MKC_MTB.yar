
rule Trojan_Win64_RedCap_MKC_MTB{
	meta:
		description = "Trojan:Win64/RedCap.MKC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e7 8b c7 2b c2 d1 e8 03 c2 c1 e8 05 0f b7 c0 6b c8 38 0f b7 c7 41 03 fe 66 2b c1 66 41 03 c5 66 31 06 48 8d 76 ?? 83 ff 0b 7c } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}