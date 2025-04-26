
rule Trojan_Win64_BlackWidow_MLU_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.MLU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 f7 f1 c5 fd 67 c0 c5 f5 67 c9 c5 ed fd d6 c5 e5 fd df c5 ed 67 d2 c5 e5 67 db c5 dd fd e6 c5 d5 fd ef c5 dd 67 e4 c5 d5 67 ed c5 fd 60 c2 c5 dd 60 e1 c5 e5 60 dd c5 c5 73 d8 ?? 45 8a 14 10 c5 e5 61 df c5 dd 69 e9 c5 dd 61 e1 c5 fd 70 f8 4e c5 fd 62 c3 c5 e5 6a dc c5 f5 ef c9 c5 e5 75 db c5 e5 71 f3 07 c4 e3 fd 00 f6 d8 c4 e3 fd 00 ff d8 44 30 14 0f c4 e3 fd 00 f6 d8 c4 e3 fd 00 ff } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}