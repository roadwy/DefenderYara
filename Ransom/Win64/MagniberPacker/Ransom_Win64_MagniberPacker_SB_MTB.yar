
rule Ransom_Win64_MagniberPacker_SB_MTB{
	meta:
		description = "Ransom:Win64/MagniberPacker.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {a0 74 46 02 4c a1 65 8a fa 4c f2 8d 66 90 01 01 68 90 01 04 cd 90 01 01 6a 90 01 01 ba 90 01 04 85 29 80 a0 90 01 05 c9 33 89 90 01 04 e1 90 01 01 34 90 01 01 13 e1 79 90 00 } //02 00 
	condition:
		any of ($a_*)
 
}