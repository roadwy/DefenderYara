
rule Ransom_Win64_MagniberPacker_SF_MTB{
	meta:
		description = "Ransom:Win64/MagniberPacker.SF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 e2 41 b1 ?? 66 64 81 5d ?? ?? ?? bc ?? ?? ?? ?? a8 ?? 1d ?? ?? ?? ?? a1 ?? ?? ?? ?? ?? ?? ?? ?? ed 84 18 2d ?? ?? ?? ?? 30 52 ?? 38 1e 31 67 ?? 7e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}