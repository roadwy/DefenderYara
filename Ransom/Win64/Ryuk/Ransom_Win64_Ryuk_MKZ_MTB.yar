
rule Ransom_Win64_Ryuk_MKZ_MTB{
	meta:
		description = "Ransom:Win64/Ryuk.MKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {41 8b d1 2b d0 48 63 c2 49 63 d1 41 ff c1 0f b6 84 18 ?? ?? ?? ?? 41 32 00 49 ff c0 41 88 02 49 ff c2 49 63 c1 48 3d 0d 08 00 00 72 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}