
rule Ransom_Win64_MagniberPacker_SF_MTB{
	meta:
		description = "Ransom:Win64/MagniberPacker.SF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 e2 41 b1 90 01 01 66 64 81 5d 90 01 03 bc 90 01 04 a8 90 01 01 1d 90 01 04 a1 90 01 08 ed 84 18 2d 90 01 04 30 52 90 01 01 38 1e 31 67 90 01 01 7e 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}