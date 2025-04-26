
rule Trojan_Win64_BlackWidow_MPZ_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.MPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 f7 f1 44 0f 14 c0 44 0f 14 c9 66 0f 70 e2 ?? 66 0f 70 eb 00 66 41 0f d9 c0 66 41 0f d9 c1 66 41 0f d9 c2 66 41 0f d9 c3 66 41 0f d9 c4 45 8a 14 10 66 41 0f d9 c4 66 41 0f d9 c2 66 41 0f d9 c6 66 41 0f d9 c7 66 0f f1 d3 66 0f f1 d0 66 0f f2 da 0f 28 d8 0f 14 d1 66 0f 70 ec 00 66 0f 38 de d1 44 30 14 0f 66 0f 38 de f1 66 0f 38 de f9 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}