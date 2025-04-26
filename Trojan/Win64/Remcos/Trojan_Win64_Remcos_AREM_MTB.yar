
rule Trojan_Win64_Remcos_AREM_MTB{
	meta:
		description = "Trojan:Win64/Remcos.AREM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {49 ff c1 45 89 dd 31 d3 41 0f b6 d3 41 c1 ed 18 8b 94 ?? ?? ?? ?? ?? 42 33 14 a8 44 0f b6 eb 42 33 94 a8 ?? ?? ?? ?? 41 89 dd 41 c1 ed 18 42 33 94 a8 ?? ?? ?? ?? 41 89 d6 44 89 da 41 c1 eb 10 0f b6 d6 45 0f b6 db 41 89 d5 42 8b 94 a8 ?? ?? ?? ?? 44 31 f2 42 33 94 98 ?? ?? ?? ?? 41 89 d7 0f b6 d7 c1 eb 10 41 89 d3 0f b6 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}