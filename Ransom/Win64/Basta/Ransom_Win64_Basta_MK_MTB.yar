
rule Ransom_Win64_Basta_MK_MTB{
	meta:
		description = "Ransom:Win64/Basta.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 8b 10 40 8a c7 40 8a cf 81 c7 ?? ?? ?? ?? c1 c7 ?? 41 02 04 11 d2 c0 41 88 04 11 49 ff c1 48 83 ee ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}