
rule Ransom_Linux_ESXiArgs_B_MTB{
	meta:
		description = "Ransom:Linux/ESXiArgs.B!MTB,SIGNATURE_TYPE_ELFHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 7d e8 e8 [0-06] 48 83 7d d0 4f 76 ?? 48 8b 7d e8 48 83 c7 30 48 8b 55 d8 48 8b 75 e0 b9 50 00 00 00 e8 [0-06] 48 83 45 e0 50 48 83 45 d8 50 48 83 6d d0 50 eb ?? 48 8b 7d e8 48 83 c7 30 48 8b 4d d0 48 8b 55 d8 48 8b 75 e0 e8 [0-06] 48 8b 45 d0 89 c2 48 8b 45 e8 89 90 90 80 00 00 00 48 c7 45 d0 00 00 00 00 48 83 7d d0 00 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}