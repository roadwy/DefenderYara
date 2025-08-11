
rule Trojan_Win64_Donut_PGD_MTB{
	meta:
		description = "Trojan:Win64/Donut.PGD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 04 ?? ?? ?? ?? 32 04 16 31 cf c0 ?? ?? 83 c1 ?? 41 89 f8 44 31 c0 88 04 16 48 83 c2 01 48 81 fa ?? ?? ?? ?? 75 } //5
		$a_03_1 = {0f b6 84 04 ?? ?? ?? ?? 32 04 13 31 ce c0 ?? ?? 83 c1 ?? 41 89 f0 44 31 c0 88 04 13 48 83 c2 01 48 81 fa ?? ?? ?? ?? 75 } //5
	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=5
 
}