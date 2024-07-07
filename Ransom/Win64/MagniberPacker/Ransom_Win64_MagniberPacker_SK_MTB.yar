
rule Ransom_Win64_MagniberPacker_SK_MTB{
	meta:
		description = "Ransom:Win64/MagniberPacker.SK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {3c 3c 57 4b 15 90 01 04 66 98 1b 6c 6c 90 01 01 0b 5b 90 01 01 b4 90 01 01 41 6d 33 18 18 5f 90 01 01 55 d3 c4 31 f0 3a 57 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}