
rule Ransom_Win64_Booran_PB_MTB{
	meta:
		description = "Ransom:Win64/Booran.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {4c 89 e9 e8 ?? ?? ?? ?? 48 8b 8d ?? ?? ?? ?? 31 04 b9 48 ff c7 48 39 fe 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}