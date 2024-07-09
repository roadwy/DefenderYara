
rule Ransom_Win64_Magniber_PAB_MTB{
	meta:
		description = "Ransom:Win64/Magniber.PAB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 33 d2 eb 90 0a 05 00 48 33 d2 90 13 32 c0 90 13 8a a6 ?? ?? ?? ?? 90 13 32 a6 ?? ?? ?? ?? 90 13 32 e0 90 13 8a c4 90 13 88 27 90 13 48 ff c6 90 13 48 ff c7 90 13 48 ff c2 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}