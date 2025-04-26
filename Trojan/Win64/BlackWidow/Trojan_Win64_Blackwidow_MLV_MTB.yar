
rule Trojan_Win64_Blackwidow_MLV_MTB{
	meta:
		description = "Trojan:Win64/Blackwidow.MLV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {c5 f5 ef c9 c5 e5 75 db c5 e5 71 f3 ?? c5 cd 60 e1 c5 cd 68 f1 c5 c5 60 c1 49 f7 f1 c5 d5 fd f5 c5 ed fd e2 c5 f5 fd f9 c5 e5 fd c3 c5 cd 75 f6 45 8a 14 10 c5 fd fd c6 c5 f5 fd cf c5 fd 67 c0 } //5
		$a_03_1 = {dd 61 e1 c5 fd 70 f8 4e c5 fd 62 c3 c5 e5 6a dc 48 89 c8 c4 e3 fd 00 f6 ?? c4 e3 fd 00 ff d8 c5 cd 60 e1 c5 cd 68 f1 c5 c5 60 c1 48 81 f9 d3 25 1c 00 0f 86 } //4
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*4) >=9
 
}