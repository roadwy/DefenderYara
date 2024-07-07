
rule Trojan_Win32_Hancitor_GI_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.GI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c8 03 0d 90 02 04 89 35 90 02 04 01 0d 90 02 04 8a cb 2a c8 a1 90 02 04 80 e9 90 01 01 3b 05 90 02 04 88 0d 90 02 04 90 18 8b 4c 24 90 01 01 8d 14 1b 2b 15 90 02 04 81 c5 90 02 04 2b d7 89 29 83 c1 04 83 6c 24 90 01 01 01 8d 84 10 90 02 04 89 2d 90 02 04 a3 90 02 04 89 4c 24 90 01 01 0f 85 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}