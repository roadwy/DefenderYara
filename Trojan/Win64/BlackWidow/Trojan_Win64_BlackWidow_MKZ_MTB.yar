
rule Trojan_Win64_BlackWidow_MKZ_MTB{
	meta:
		description = "Trojan:Win64/BlackWidow.MKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 f7 f1 66 0f 62 c1 45 8a 14 10 45 0f 5f ca 45 0f 5d dc 45 0f 52 d6 44 0f c2 f8 ?? c5 f1 61 c2 c5 d9 6a dd c4 c1 41 f9 f0 c5 f5 61 c2 c5 dd 6a dd 44 30 14 0f 66 0f 6a f9 48 ff c1 66 0f 6a d5 48 89 c8 66 0f 6d ce 48 81 f9 d3 3b 01 00 76 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}