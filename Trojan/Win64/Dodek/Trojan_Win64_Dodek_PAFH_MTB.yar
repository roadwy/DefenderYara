
rule Trojan_Win64_Dodek_PAFH_MTB{
	meta:
		description = "Trojan:Win64/Dodek.PAFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 bb ed 5b e1 81 b1 ad d3 7f 66 ?? 43 8d ?? ?? 80 e1 07 c0 e1 03 49 8b d3 48 d3 ea 41 30 50 ff 41 0f b6 c8 41 2a c9 80 e1 07 c0 e1 03 49 8b d3 48 d3 ea 41 30 10 49 83 c0 02 4b 8d ?? ?? 48 83 f8 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}