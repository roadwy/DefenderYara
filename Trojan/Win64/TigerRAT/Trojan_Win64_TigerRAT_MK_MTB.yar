
rule Trojan_Win64_TigerRAT_MK_MTB{
	meta:
		description = "Trojan:Win64/TigerRAT.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c2 89 43 ?? 0f b6 c0 03 43 ?? 69 c8 ?? ?? ?? ?? ff c1 89 4b ?? 0f b6 43 ?? 41 ?? ?? ?? 48 33 c8 41 c1 e8 ?? 41 ?? ?? ?? 41 33 c0 89 43 ?? 41 8b c1 83 f0 ?? 41 ?? ?? ?? c1 e8 ?? 41 32 c2 42 88 ?? ?? ?? 4d 3b dd 7c } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}