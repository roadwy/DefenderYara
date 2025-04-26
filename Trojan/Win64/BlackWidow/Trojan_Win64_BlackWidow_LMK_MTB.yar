
rule Trojan_Win64_BlackWidow_LMK_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.LMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {c5 cd 68 f1 49 f7 f1 c5 d5 fd f5 c5 ed fd e2 c5 f5 fd f9 45 8a 14 10 66 0f 38 de f1 66 0f 38 de f9 66 44 0f 38 de c1 66 44 0f 38 de c9 44 30 14 0f c5 cd fd eb c5 dd fd d3 c5 c5 fd cb c5 fd fd db c5 d5 fd f5 48 ff c1 c5 fd 6f da c5 fd 6f ec c5 fd fd c6 48 89 c8 ?? 48 81 f9 d3 3d 01 00 0f 86 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}