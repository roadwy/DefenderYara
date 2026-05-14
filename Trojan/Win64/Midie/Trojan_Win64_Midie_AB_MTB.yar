
rule Trojan_Win64_Midie_AB_MTB{
	meta:
		description = "Trojan:Win64/Midie.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {40 20 f2 b3 52 41 20 d8 41 08 d0 44 30 e0 08 c1 40 20 f0 41 20 db 41 08 c3 45 30 c3 40 30 f9 44 08 d9 40 30 f9 44 89 d0 20 c8 44 30 d1 08 c1 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Midie_AB_MTB_2{
	meta:
		description = "Trojan:Win64/Midie.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 03 c8 48 8b c1 0f b7 4c 24 38 c1 e1 ?? 48 63 c9 8b 04 08 89 44 24 2c b8 ?? 00 00 00 } //20
		$a_01_1 = {48 8b 4c 24 30 48 03 c8 48 8b c1 8b 4c 24 28 d1 e1 8b c9 0f b7 04 08 } //30
	condition:
		((#a_03_0  & 1)*20+(#a_01_1  & 1)*30) >=50
 
}