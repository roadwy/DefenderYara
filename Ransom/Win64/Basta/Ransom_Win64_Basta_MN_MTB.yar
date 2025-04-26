
rule Ransom_Win64_Basta_MN_MTB{
	meta:
		description = "Ransom:Win64/Basta.MN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 8b 10 40 8a cf 41 8a 04 12 40 2a c7 69 ff ?? ?? ?? ?? d2 c0 41 88 04 12 49 ff c2 81 c7 ?? ?? ?? ?? 48 83 ee ?? 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}