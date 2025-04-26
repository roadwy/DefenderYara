
rule Trojan_Win64_BlackWidow_UTD_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.UTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_01_0 = {49 f7 f1 c5 fd 6f da c5 fd 6f ec c5 fd fd c6 c5 f5 fd cf c5 fd 67 c0 c5 f5 67 c9 c5 ed fd d6 c5 e5 fd df c5 ed 67 d2 c5 e5 67 db 45 8a 14 10 c5 dd fd e6 c5 d5 fd ef c5 dd 67 e4 c5 d5 67 ed c5 fd 60 c2 c5 dd 60 e1 44 30 14 0f c5 c5 73 d8 02 } //5
		$a_03_1 = {48 ff c1 c5 f5 ef c9 c5 e5 75 db c5 e5 71 f3 07 c4 e3 fd 00 f6 d8 c4 e3 fd 00 ff d8 c5 cd 60 e1 c5 cd 68 f1 c5 c5 60 c1 48 89 c8 c5 e5 67 db c5 dd fd e6 c5 d5 fd ef c5 dd 67 e4 c5 d5 67 ed c5 fd 60 c2 c5 dd 60 e1 c5 e5 60 dd c5 c5 73 d8 ?? c5 fd 69 f4 c5 fd 61 c4 48 81 f9 d3 41 00 00 0f 86 } //4
	condition:
		((#a_01_0  & 1)*5+(#a_03_1  & 1)*4) >=9
 
}