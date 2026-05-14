
rule Trojan_Win64_ValleyRAT_PGVA_MTB{
	meta:
		description = "Trojan:Win64/ValleyRAT.PGVA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 8b 7c 24 78 49 31 f1 49 c1 c9 18 4d 01 ca 4c 89 94 24 38 01 00 00 49 31 ca 48 8d 0c 2f 49 c1 ca 10 4c 01 c1 4c 01 d6 4c 89 94 24 90 01 00 00 48 89 b4 24 88 01 00 00 48 31 ca 4c 31 ce } //5
		$a_01_1 = {f3 0f 6f 00 48 83 c2 10 66 0f ef 42 f0 48 83 c0 10 66 0f ef 42 30 0f 11 40 f0 48 39 d1 75 e1 } //5
		$a_03_2 = {48 89 c2 83 e2 07 0f b6 54 14 [0-02] 30 54 05 00 48 83 c0 01 [0-01] 39 [0-01] 75 } //5
	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5+(#a_03_2  & 1)*5) >=5
 
}