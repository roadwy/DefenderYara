
rule Trojan_Win64_Bumblebee_TYP_MTB{
	meta:
		description = "Trojan:Win64/Bumblebee.TYP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {44 29 d0 29 c1 88 ca 0f b6 c2 41 89 c0 43 0f b6 44 01 ?? 4c 8b 44 24 18 4c 63 5c 24 ?? 43 0f b6 0c 18 41 89 ca 41 83 f2 ff 89 c6 44 21 d6 83 f0 ff 21 c1 09 ce 40 88 f2 43 88 14 18 31 c0 8b 4c 24 08 83 e8 01 29 c1 89 4c 24 08 e9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}