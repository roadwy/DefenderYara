
rule Ransom_Win64_Magniber_DA_MTB{
	meta:
		description = "Ransom:Win64/Magniber.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b d6 45 8d 7c 24 01 48 8b d8 49 8b ce 40 30 39 41 03 ff 81 ff ff 00 00 00 41 0f 44 ff 49 03 cf 49 2b d7 75 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}