
rule Ransom_Win64_MedusaLocker_YBG_MTB{
	meta:
		description = "Ransom:Win64/MedusaLocker.YBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {48 89 94 24 e0 05 00 00 0f b6 84 14 a0 05 00 00 30 04 1e 48 8b 94 24 e0 05 00 00 48 ff c2 48 89 94 24 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}