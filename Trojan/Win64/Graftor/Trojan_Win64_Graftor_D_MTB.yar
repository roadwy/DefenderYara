
rule Trojan_Win64_Graftor_D_MTB{
	meta:
		description = "Trojan:Win64/Graftor.D!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 2a db d3 e2 41 81 f6 ?? ?? ?? ?? 4c 2b d3 8b 48 ?? 41 0f ab c6 45 12 f0 41 d3 de 4c 8b f3 d3 e7 49 0f 45 eb 48 ff cd 66 41 ff c2 48 8b 8c 24 ?? ?? ?? ?? ff ca 41 0f 99 c2 ff cf 66 41 0f a3 ca 66 41 0f ac f2 ?? 40 0f ?? ?? 8b eb 41 b2 ?? 45 0f c0 d2 45 8b d4 89 7c 24 ?? 40 d2 d7 8b 38 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}