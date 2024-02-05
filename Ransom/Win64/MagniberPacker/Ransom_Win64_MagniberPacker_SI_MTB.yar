
rule Ransom_Win64_MagniberPacker_SI_MTB{
	meta:
		description = "Ransom:Win64/MagniberPacker.SI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {99 4a 3e 2b 01 f7 91 90 01 04 bd 90 01 04 ec b9 90 01 04 36 38 27 90 00 } //01 00 
		$a_03_1 = {91 81 f9 53 5d bd 4e d1 2f b4 90 01 01 66 29 1f e7 90 01 01 ae 8c ae 90 01 04 32 2e 90 00 } //02 00 
	condition:
		any of ($a_*)
 
}