
rule Trojan_Win32_Dridex_DEM_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DEM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b c8 66 03 d1 8b 4c 24 ?? 0f b7 c2 66 89 15 ?? ?? ?? ?? 99 2b c8 0f b7 c6 1b fa 83 c1 ?? 99 83 d7 ?? 3b c8 90 13 a1 [0-0f] 03 c3 03 c5 66 a3 ?? ?? ?? ?? 8b 44 24 ?? 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 89 01 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}