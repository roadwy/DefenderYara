
rule Trojan_Win32_Hancitor_GI_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c8 03 0d [0-04] 89 35 [0-04] 01 0d [0-04] 8a cb 2a c8 a1 [0-04] 80 e9 ?? 3b 05 [0-04] 88 0d [0-04] 90 18 8b 4c 24 ?? 8d 14 1b 2b 15 [0-04] 81 c5 [0-04] 2b d7 89 29 83 c1 04 83 6c 24 ?? 01 8d 84 10 [0-04] 89 2d [0-04] a3 [0-04] 89 4c 24 ?? 0f 85 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}