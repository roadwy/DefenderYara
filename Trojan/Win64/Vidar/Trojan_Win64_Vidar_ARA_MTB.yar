
rule Trojan_Win64_Vidar_ARA_MTB{
	meta:
		description = "Trojan:Win64/Vidar.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 32 04 16 ?? 88 44 ?? ff 44 0f b6 04 ?? 48 89 ?? 48 09 ?? 48 c1 e8 20 75 a2 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}
rule Trojan_Win64_Vidar_ARA_MTB_2{
	meta:
		description = "Trojan:Win64/Vidar.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {41 0f b6 08 ff c2 83 e1 0f 4a 0f be 84 11 e0 54 01 00 42 8a 8c 11 f0 54 01 00 4c 2b c0 41 8b 40 fc d3 e8 4c 89 47 08 89 47 18 41 0f b6 08 83 e1 0f } //2
	condition:
		((#a_01_0  & 1)*2) >=2
 
}