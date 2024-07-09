
rule Trojan_Win32_Hancitor_FGS_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.FGS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f af c1 69 c0 f2 b0 00 00 02 d9 80 eb 06 83 c5 04 81 fd a2 0d 00 00 8a d3 0f b7 c8 0f 82 90 09 1d 00 a1 ?? ?? ?? ?? 81 c7 1c d3 0d 01 89 3d ?? ?? ?? ?? 89 bc 28 ?? ?? ?? ?? a1 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}