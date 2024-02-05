
rule Ransom_Win64_MagniberPacker_SM_MTB{
	meta:
		description = "Ransom:Win64/MagniberPacker.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {1a 32 b6 36 18 17 c3 4f 1b 53 90 01 01 4c fa de 3c 13 32 56 90 01 01 36 45 90 00 } //01 00 
		$a_03_1 = {32 08 5e f2 e6 90 01 01 7d 90 00 } //02 00 
	condition:
		any of ($a_*)
 
}