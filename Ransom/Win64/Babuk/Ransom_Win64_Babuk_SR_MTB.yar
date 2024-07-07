
rule Ransom_Win64_Babuk_SR_MTB{
	meta:
		description = "Ransom:Win64/Babuk.SR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 33 c9 48 89 46 90 01 01 44 8b c7 8b d7 33 c9 ff 15 90 01 04 45 33 c9 44 8b c7 33 d2 48 89 06 33 c9 ff 15 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}