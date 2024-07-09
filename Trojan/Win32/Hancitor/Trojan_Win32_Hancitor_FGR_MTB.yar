
rule Trojan_Win32_Hancitor_FGR_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.FGR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b ea 83 ed 06 89 2d ?? ?? ?? ?? 8b 54 24 10 69 d2 f7 1e 00 00 2b ca 0f b7 c1 8b 0d ?? ?? ?? ?? 81 c7 20 1c 00 01 0f b7 d0 89 3d ?? ?? ?? ?? 89 bc 31 90 09 14 00 8b bc 37 ?? ?? ?? ?? a3 ?? ?? ?? ?? 72 ?? 29 15 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}