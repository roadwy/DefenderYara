
rule Trojan_Win64_BlackWidow_MIP_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.MIP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 31 d2 c5 f5 ef c9 49 f7 f1 c5 e5 75 db c5 e5 71 f3 ?? 45 8a 14 10 c5 ed fd e2 c5 f5 fd f9 c5 e5 fd c3 c5 cd 75 f6 c5 cd 71 d6 ?? c5 cd db f7 44 30 14 0f c5 c5 fd cb 48 ff c1 c5 e5 67 db 48 89 c8 c5 fd 69 f4 48 81 f9 d3 3b 01 00 76 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}