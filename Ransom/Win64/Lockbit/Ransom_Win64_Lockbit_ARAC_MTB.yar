
rule Ransom_Win64_Lockbit_ARAC_MTB{
	meta:
		description = "Ransom:Win64/Lockbit.ARAC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b c1 48 2b c3 83 e0 1f 42 0f b6 04 00 32 01 32 c2 ?? ?? ?? ?? 48 ff c1 3b ?? 72 e3 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}