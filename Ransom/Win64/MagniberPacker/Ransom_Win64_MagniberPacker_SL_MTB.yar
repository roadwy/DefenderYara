
rule Ransom_Win64_MagniberPacker_SL_MTB{
	meta:
		description = "Ransom:Win64/MagniberPacker.SL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f2 b1 f7 7c 90 01 01 4c 87 e4 eb 90 01 01 66 c9 33 89 90 01 04 e1 90 01 01 34 90 01 01 13 e1 79 90 01 01 4c 8b d1 eb 90 01 01 d1 05 90 01 04 da 2c 2d 90 01 04 74 90 01 01 02 2e 2c 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}