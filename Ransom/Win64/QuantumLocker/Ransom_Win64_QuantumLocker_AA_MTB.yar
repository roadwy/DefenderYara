
rule Ransom_Win64_QuantumLocker_AA_MTB{
	meta:
		description = "Ransom:Win64/QuantumLocker.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f b7 44 24 90 01 01 66 ff c0 66 89 44 24 90 01 01 0f b7 44 24 90 01 01 0f b7 4c 24 90 01 01 3b c1 7d 90 01 01 8b 4c 24 90 01 01 e8 90 01 04 89 44 24 90 01 01 0f b7 44 24 90 01 01 48 8b 4c 24 90 01 01 0f b6 04 01 0f b6 4c 24 90 01 01 33 c1 0f b7 4c 24 90 01 01 48 8b 54 24 90 01 01 88 04 0a eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}