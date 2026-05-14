
rule Trojan_Win64_Vidar_KG_MTB{
	meta:
		description = "Trojan:Win64/Vidar.KG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {49 8b 14 24 48 c1 ea ?? 48 31 c2 49 89 14 24 49 8b 07 49 01 04 24 49 8b 07 83 3d } //1
		$a_03_1 = {44 0f af c2 41 83 e0 ?? 74 ?? 49 69 07 ?? ?? ?? ?? 49 f7 e6 48 c1 ea ?? 48 ff c2 49 89 17 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}