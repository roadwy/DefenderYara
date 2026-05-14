
rule Trojan_Win64_Fragtor_SXF_MTB{
	meta:
		description = "Trojan:Win64/Fragtor.SXF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,32 00 32 00 02 00 00 "
		
	strings :
		$a_03_0 = {f8 ff ff e2 00 07 00 c7 85 ?? f8 ff ff 94 00 9f 00 c7 85 ?? f8 ff ff 9c 00 7f 00 c7 85 ?? f8 ff ff 89 00 33 00 c7 85 ?? f8 ff ff 60 00 ab 00 } //30
		$a_03_1 = {8b ce 69 c6 95 ff 00 00 83 e1 03 ba b0 f3 d9 45 c1 e1 03 d3 ea 33 d0 0f b6 c2 66 33 84 ?? a4 f8 ff ff 8b 95 ?? ?? ff ff 0f b7 c8 } //20
	condition:
		((#a_03_0  & 1)*30+(#a_03_1  & 1)*20) >=50
 
}