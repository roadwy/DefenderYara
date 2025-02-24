
rule Trojan_Win64_Emotet_GB_MTB{
	meta:
		description = "Trojan:Win64/Emotet.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b cb 41 8b d0 d3 e2 41 8b cb d3 e0 03 d0 41 0f be ?? 03 d0 41 2b d0 49 ff c1 44 8b c2 } //1
		$a_02_1 = {44 8b c0 44 8b ?? 41 8b cb 41 d3 ?? 8b cb d3 e0 8b c8 8d 42 ?? 66 83 f8 ?? 0f b7 c2 77 ?? 83 c0 ?? 41 2b ?? 41 03 ?? 03 c1 49 83 [0-02] 41 0f b7 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}