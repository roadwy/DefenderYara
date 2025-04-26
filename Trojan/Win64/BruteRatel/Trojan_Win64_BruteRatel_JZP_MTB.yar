
rule Trojan_Win64_BruteRatel_JZP_MTB{
	meta:
		description = "Trojan:Win64/BruteRatel.JZP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 f7 f1 c5 e5 72 d4 14 45 8a 14 10 66 0f f5 d1 66 0f d9 d0 66 0f 61 de 66 0f 61 ce 66 0f fd dc 66 0f fd ca 0f 12 d1 66 0f fd ca 66 0f eb e5 66 0f ef c0 66 0f fd dc 66 0f fd ca c4 c1 5d ef e0 c5 fd fe c4 44 30 14 0f c5 dd 72 f4 ?? 48 ff c1 c5 dd ef e3 48 89 c8 c5 fd fe c4 48 81 f9 d3 47 0a 00 76 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}