
rule Ransom_Win64_MagniberPacker_SE_MTB{
	meta:
		description = "Ransom:Win64/MagniberPacker.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ba 4b eb 25 cf 32 9d 90 01 05 15 90 01 04 31 0a f7 3f 22 61 90 01 01 dc 5e 90 01 01 10 9c d8 90 01 04 02 85 90 01 04 2b 23 a2 90 00 } //01 00 
		$a_00_1 = {42 4d 77 55 57 68 79 54 71 68 77 73 } //02 00  BMwUWhyTqhws
	condition:
		any of ($a_*)
 
}