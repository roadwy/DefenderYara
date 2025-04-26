
rule Trojan_Win64_BlackWidow_MMD_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.MMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 f7 f1 66 0f 38 40 d6 45 8a 14 10 66 0f 38 40 d6 0f 28 dc 0f 28 d5 0f 14 e7 0f 14 ee 0f 28 c3 66 0f 70 dc ?? 44 30 14 0f c4 e2 6d 40 d4 48 ff c1 66 0f 70 dc ?? 66 0f 70 e5 00 48 89 c8 66 0f 70 fa 00 48 81 f9 d3 3d 01 00 76 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}