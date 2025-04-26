
rule Ransom_Win64_Babuk_SR_MTB{
	meta:
		description = "Ransom:Win64/Babuk.SR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 33 c9 48 89 46 ?? 44 8b c7 8b d7 33 c9 ff 15 ?? ?? ?? ?? 45 33 c9 44 8b c7 33 d2 48 89 06 33 c9 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}