
rule Trojan_Win64_Lazy_PGLY_MTB{
	meta:
		description = "Trojan:Win64/Lazy.PGLY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {cb b5 d9 4b df e6 9c 43 08 a2 00 31 0b ea 2b 2a 49 2d a7 e1 ff fa 12 c9 e9 97 e6 db 9f 8e e2 1f 12 3d 12 cb 15 a3 a7 c0 9d 66 fd } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Lazy_PGLY_MTB_2{
	meta:
		description = "Trojan:Win64/Lazy.PGLY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {19 4a 0a a4 03 8e b2 56 bc 45 bf 9f 87 da e4 eb 9a af 1e 52 4c 45 c1 05 ef 39 e4 d1 f7 fa 6a ea 96 5e cb 83 d5 24 93 ef 89 17 4d 61 fe 92 4f 72 25 22 1f c2 60 26 1d f7 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}
rule Trojan_Win64_Lazy_PGLY_MTB_3{
	meta:
		description = "Trojan:Win64/Lazy.PGLY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {40 a3 fb a6 08 f4 81 71 8d b2 05 1f ae 81 82 69 51 7b ea 61 3d a6 fb 9e 0d 6f b8 8e 3b 20 b5 0f d1 4b 07 69 c5 34 df f5 2a 75 60 e3 d0 54 83 fa 36 a5 d1 84 99 ee 1e 75 78 04 b1 39 } //5
	condition:
		((#a_01_0  & 1)*5) >=5
 
}