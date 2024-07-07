
rule Ransom_Win64_BastaPacker_ZC_MTB{
	meta:
		description = "Ransom:Win64/BastaPacker.ZC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 98 4c 8d 04 02 48 8b 95 90 01 04 8b 85 90 01 04 48 98 48 01 d0 44 0f b6 08 8b 8d 90 01 04 ba 90 01 04 89 c8 f7 ea c1 fa 90 01 01 89 c8 c1 f8 90 01 01 29 c2 89 d0 6b c0 90 01 01 29 c1 89 c8 48 63 d0 48 8b 85 90 01 04 48 01 d0 0f b6 00 44 31 c8 41 88 00 83 85 90 01 04 01 8b 85 90 01 04 48 63 d0 48 8b 85 90 01 04 48 39 c2 72 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}