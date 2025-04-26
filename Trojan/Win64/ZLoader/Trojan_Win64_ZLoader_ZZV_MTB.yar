
rule Trojan_Win64_ZLoader_ZZV_MTB{
	meta:
		description = "Trojan:Win64/ZLoader.ZZV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 ca 48 c1 ea 3f 48 c1 f9 ?? 01 d1 89 ca c1 e2 04 01 ca 89 c1 29 d1 48 63 c9 42 0f b6 0c 31 32 0c 06 88 0c 07 75 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}