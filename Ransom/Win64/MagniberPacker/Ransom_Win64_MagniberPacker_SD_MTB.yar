
rule Ransom_Win64_MagniberPacker_SD_MTB{
	meta:
		description = "Ransom:Win64/MagniberPacker.SD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {32 ae a0 0d 00 00 e9 90 01 04 a0 90 01 08 96 bc 90 01 04 d2 eb 76 90 01 01 7a 90 01 01 94 e5 90 01 01 eb 90 01 01 05 aa 48 81 fa 94 01 01 00 eb e9 90 01 04 a2 90 01 08 48 90 01 02 eb 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}