
rule Ransom_Win64_QuantumLocker_AA_MTB{
	meta:
		description = "Ransom:Win64/QuantumLocker.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b7 44 24 ?? 66 ff c0 66 89 44 24 ?? 0f b7 44 24 ?? 0f b7 4c 24 ?? 3b c1 7d ?? 8b 4c 24 ?? e8 ?? ?? ?? ?? 89 44 24 ?? 0f b7 44 24 ?? 48 8b 4c 24 ?? 0f b6 04 01 0f b6 4c 24 ?? 33 c1 0f b7 4c 24 ?? 48 8b 54 24 ?? 88 04 0a eb } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}