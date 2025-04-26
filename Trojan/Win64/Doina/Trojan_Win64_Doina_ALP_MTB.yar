
rule Trojan_Win64_Doina_ALP_MTB{
	meta:
		description = "Trojan:Win64/Doina.ALP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 03 c2 33 c8 8d 04 32 33 c8 44 2b e9 41 8b cd 41 8b c5 c1 e9 05 c1 e0 04 41 03 c9 41 03 c7 33 c8 42 8d 04 2a 81 c2 47 86 c8 61 33 c8 2b f1 41 ff c8 75 bf } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}