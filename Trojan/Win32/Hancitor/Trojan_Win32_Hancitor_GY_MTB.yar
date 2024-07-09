
rule Trojan_Win32_Hancitor_GY_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.GY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b7 e9 8b d3 2b d7 03 15 [0-04] 8b c5 2b c3 83 e8 ?? 8b fa 8b 16 3b 05 [0-04] 90 18 2b c1 03 05 [0-04] 81 c2 [0-04] 0f b7 c8 0f b7 c1 2b c7 89 16 83 c0 ?? 83 c6 ?? 83 6c 24 ?? 01 89 15 [0-04] a3 [0-04] 0f 85 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}