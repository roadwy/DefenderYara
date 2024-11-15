
rule Trojan_Win64_Latrodectus_ZSS_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.ZSS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 89 c7 49 f7 e1 48 29 d1 48 d1 e9 48 01 ca 48 c1 ea 04 48 8d 04 52 48 c1 e0 ?? 48 29 d0 48 29 c7 0f b6 44 3c ?? 43 32 04 10 48 8b 54 24 ?? 42 88 04 02 49 83 c0 01 4c 39 44 24 40 77 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}