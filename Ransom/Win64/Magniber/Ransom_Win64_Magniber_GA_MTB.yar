
rule Ransom_Win64_Magniber_GA_MTB{
	meta:
		description = "Ransom:Win64/Magniber.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a a6 e1 09 00 00 90 13 32 e0 90 13 80 f4 fe 90 13 88 27 90 13 8a c4 90 13 48 ff c6 90 13 48 ff c7 90 13 48 ff c1 90 13 48 81 f9 8b 9c 00 00 90 13 72 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}