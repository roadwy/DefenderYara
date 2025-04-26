
rule Trojan_Win64_Emotet_PBC_MTB{
	meta:
		description = "Trojan:Win64/Emotet.PBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b cb 41 8b d0 d3 e2 41 8b cb d3 e0 03 d0 41 0f be c1 03 d0 41 2b d0 49 ff ?? 44 8b c2 45 8a ?? 41 8b c0 45 84 c9 75 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}