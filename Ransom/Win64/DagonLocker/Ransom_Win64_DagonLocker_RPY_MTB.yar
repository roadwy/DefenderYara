
rule Ransom_Win64_DagonLocker_RPY_MTB{
	meta:
		description = "Ransom:Win64/DagonLocker.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {4c 8b d0 48 85 c0 74 4c 48 8b 84 24 50 01 00 00 4c 8b ce 48 89 44 24 40 4c 8b c5 8b 84 24 48 01 00 00 41 8b d6 89 44 24 38 49 8b cf 48 8b 84 24 40 01 00 00 48 89 44 24 30 8b 84 24 38 01 00 00 89 44 24 28 8b 84 24 30 01 00 00 89 44 24 20 41 ff d2 8b d8 48 8b cf ff 15 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}