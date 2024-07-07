
rule Ransom_Win64_MagniberPacker_SH_MTB{
	meta:
		description = "Ransom:Win64/MagniberPacker.SH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b1 c9 98 3c 7c 2b 6e 90 01 01 3b 39 24 90 01 01 a3 90 01 08 ae 8e 96 90 01 04 31 ac 97 90 01 04 73 90 01 01 a9 90 01 04 eb 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}