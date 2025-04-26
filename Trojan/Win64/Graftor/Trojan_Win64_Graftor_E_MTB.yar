
rule Trojan_Win64_Graftor_E_MTB{
	meta:
		description = "Trojan:Win64/Graftor.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 89 19 48 c1 c9 ?? 8b 40 ?? 66 0b cc 66 41 0f 45 c9 66 f7 d1 89 54 24 ?? f8 87 c9 8d 0c 07 b8 ?? ?? ?? ?? 41 3a f1 f8 89 7c 24 ?? 66 81 fc ?? ?? d3 e0 f5 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}