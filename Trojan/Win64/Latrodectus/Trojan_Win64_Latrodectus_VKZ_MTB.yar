
rule Trojan_Win64_Latrodectus_VKZ_MTB{
	meta:
		description = "Trojan:Win64/Latrodectus.VKZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 31 d2 c4 c1 55 ef e9 49 f7 f1 66 0f 67 d7 45 8a 14 10 ?? 66 0f 6f fd 66 0f eb d3 66 0f fe f2 66 0f fe fa 66 0f 6f d8 44 30 14 0f 66 0f f6 c8 51 48 31 f9 59 48 ff c1 66 0f 73 ff ?? 48 89 c8 48 81 f9 d3 3b 01 00 76 } //5
	condition:
		((#a_03_0  & 1)*5) >=5
 
}