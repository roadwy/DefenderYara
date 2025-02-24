
rule Trojan_Win64_BlackWidow_MKK_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.MKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 f7 f1 c5 e5 71 f3 07 c4 e3 fd 00 f6 ?? c4 e3 fd 00 ff ?? 45 8a 14 10 c5 ed fd e2 c5 f5 fd f9 c5 e5 fd c3 44 30 14 0f c5 f5 ef c9 c5 e5 75 db 48 ff c1 c5 fd 69 f4 c5 fd 61 c4 48 89 c8 c5 fd 62 c3 48 81 f9 d3 3b 01 00 76 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}