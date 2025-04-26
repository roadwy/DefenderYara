
rule Trojan_Win64_NitrogenLdr_GA_MTB{
	meta:
		description = "Trojan:Win64/NitrogenLdr.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_02_0 = {48 8b 8c 24 ?? ?? ?? ?? 0f b6 04 01 89 ?? 24 ?? 48 63 4c 24 ?? 33 d2 48 8b c1 48 f7 b4 24 ?? ?? ?? ?? 48 8b c2 48 8b 8c } //3
		$a_02_1 = {48 8b 8c 24 [0-0d] 33 c8 8b c1 48 63 4c 24 ?? 48 8b 94 24 ?? ?? ?? ?? 88 04 0a } //1
	condition:
		((#a_02_0  & 1)*3+(#a_02_1  & 1)*1) >=4
 
}