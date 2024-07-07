
rule Ransom_Win64_DagonLocker_RPX_MTB{
	meta:
		description = "Ransom:Win64/DagonLocker.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 4b 38 44 8b 4b 04 33 c9 8b 53 38 45 8b c1 44 33 83 88 00 00 00 44 33 8b 04 01 00 00 41 81 e8 90 01 04 41 81 e9 90 01 04 ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}