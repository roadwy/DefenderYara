
rule Ransom_Win64_LockBit_PH_MTB{
	meta:
		description = "Ransom:Win64/LockBit.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 ?? 48 63 54 24 ?? 44 0f b7 04 ?? 8b 44 24 ?? 41 b9 [0-04] 99 41 f7 f9 83 c2 ?? 41 31 d0 48 63 44 24 ?? 66 44 89 ?? ?? 8b 44 24 ?? 83 c0 ?? 89 44 24 ?? eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}