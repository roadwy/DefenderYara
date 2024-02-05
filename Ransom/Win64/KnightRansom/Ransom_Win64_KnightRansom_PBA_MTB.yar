
rule Ransom_Win64_KnightRansom_PBA_MTB{
	meta:
		description = "Ransom:Win64/KnightRansom.PBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 02 00 "
		
	strings :
		$a_03_0 = {0f b7 d2 89 d5 c1 ed 0f c1 ea 06 01 ea 89 d5 c1 e5 07 29 ea 01 d1 81 c1 90 01 04 80 c1 7f 0f b6 c9 8d 14 49 c1 ea 08 89 cb 28 d3 d0 eb 00 d3 c0 eb 06 0f b6 eb 89 ea c1 e2 07 29 ea 28 d1 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}