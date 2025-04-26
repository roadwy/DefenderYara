
rule Trojan_Win64_BlackWidow_GNQ_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.GNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {c5 c5 fd cb c5 c5 73 dc ?? c5 e5 69 d7 44 30 14 0f c5 dd 60 e1 48 ff c1 c5 c5 68 f9 48 89 c8 c4 e3 fd 00 ff ?? 48 81 f9 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win64_BlackWidow_GNQ_MTB_2{
	meta:
		description = "Trojan:Win64/BlackWidow.GNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {45 8a 14 10 c5 ed fd d6 c5 e5 fd df c5 ed 67 d2 c5 e5 67 db c5 dd fd e6 c5 d5 fd ef c5 dd 67 e4 c5 d5 67 ed c5 fd 60 c2 44 30 14 0f c5 dd fd e6 c5 d5 fd ef c5 dd 67 e4 c5 d5 67 ed c5 fd 60 c2 c5 dd 60 e1 c5 e5 60 dd } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_Win64_BlackWidow_GNQ_MTB_3{
	meta:
		description = "Trojan:Win64/BlackWidow.GNQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 ?? 48 6b c0 ?? 48 2b c8 0f b6 44 0c ?? 43 32 44 08 ?? 41 88 41 ?? 49 ff cb 0f 85 } //10
		$a_03_1 = {48 8b c1 48 2b c2 48 d1 e8 48 03 c2 48 c1 e8 ?? 48 6b c0 ?? 48 2b c8 48 0f af cb 8a 44 0c ?? 43 32 04 13 41 88 02 4d 03 d4 45 3b cd } //10
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10) >=10
 
}