
rule Ransom_Win64_Magniber_PAI_MTB{
	meta:
		description = "Ransom:Win64/Magniber.PAI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 82 72 0c 00 00 90 13 32 05 90 01 04 90 13 88 05 9e 3d 01 00 90 13 88 06 90 13 48 ff c2 90 13 48 ff c6 90 13 ff 05 90 01 04 90 13 81 3d 90 01 08 90 13 90 13 8a 82 8f 0c 00 00 90 00 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}