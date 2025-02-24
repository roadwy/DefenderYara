
rule Ransom_Win64_Lockbit_PMK_MTB{
	meta:
		description = "Ransom:Win64/Lockbit.PMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 ff c0 45 0f b6 c0 46 8a 8c 04 ?? ?? ?? ?? 44 00 ca 44 0f b6 d2 46 8a 9c 14 ?? ?? ?? ?? 46 88 9c 04 e0 03 00 00 46 88 8c 14 e0 03 00 00 46 02 8c 04 e0 03 00 00 45 0f b6 c9 46 8a 8c 0c ?? ?? ?? ?? 44 30 0c 01 48 ff c0 eb } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}