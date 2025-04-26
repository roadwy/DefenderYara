
rule Ransom_Win64_LockBit_NB_MTB{
	meta:
		description = "Ransom:Win64/LockBit.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b ca 83 e1 7f 0f b6 0c 39 0f b6 84 14 ?? ?? 00 00 32 c8 88 8c 14 ?? ?? 00 00 48 ff c2 48 83 fa } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}