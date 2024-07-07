
rule Ransom_Win64_MagniberPacker_SA_MTB{
	meta:
		description = "Ransom:Win64/MagniberPacker.SA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8c 10 88 50 ab 02 1f be 90 01 04 02 53 90 01 01 ed 69 24 ab 90 01 04 e7 90 01 01 b5 90 01 01 30 52 90 01 01 38 1e 31 67 90 01 01 7e 90 01 01 d1 c8 b4 90 01 01 ef b6 90 01 01 fa b9 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}