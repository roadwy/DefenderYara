
rule Trojan_Win64_Latrodectus_ASJ_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.ASJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 f7 e1 48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 04 48 6b c0 ?? 48 2b c8 49 0f af cf 8a 44 0d ?? 43 32 04 19 41 88 03 49 ff c3 41 81 fa } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}