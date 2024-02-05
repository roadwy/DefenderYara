
rule Ransom_Win64_MagniberPacker_SJ_MTB{
	meta:
		description = "Ransom:Win64/MagniberPacker.SJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {63 d0 3a a0 90 01 04 35 90 01 04 76 90 01 01 15 90 01 04 76 90 01 01 a2 90 01 08 a1 90 01 08 70 90 01 01 ef 65 a0 90 01 08 12 54 01 90 01 01 6b 8a 90 01 05 9d 32 8d 90 00 } //02 00 
	condition:
		any of ($a_*)
 
}