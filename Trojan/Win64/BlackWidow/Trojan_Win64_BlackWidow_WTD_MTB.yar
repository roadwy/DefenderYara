
rule Trojan_Win64_BlackWidow_WTD_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.WTD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 f7 f1 c5 cd fd eb c5 dd fd d3 c5 c5 fd cb c5 fd fd db c5 d5 fd f5 c5 ed fd e2 c5 f5 fd f9 c5 e5 fd c3 45 8a 14 10 c5 cd 75 f6 c5 cd 71 d6 ?? c5 cd db f7 c5 c5 71 d7 08 c5 fd 6f c8 c5 fd 6f da c5 fd 6f ec 44 30 14 0f c5 fd fd } //5
		$a_03_1 = {48 ff c1 c5 e5 67 db c5 dd fd e6 c5 d5 fd ef c5 dd 67 e4 c5 d5 67 ed c5 fd 60 c2 c5 dd 60 e1 c5 e5 60 dd 48 89 c8 c5 fd 61 c4 c5 dd 73 dc 02 c5 f5 73 db ?? c5 e5 69 d7 c5 e5 61 df 48 81 f9 d3 41 00 00 0f 86 } //4
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*4) >=9
 
}