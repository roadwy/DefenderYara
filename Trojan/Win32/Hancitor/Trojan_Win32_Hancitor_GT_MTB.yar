
rule Trojan_Win32_Hancitor_GT_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 ca 2b c8 83 c1 90 01 01 c7 05 90 01 04 00 00 00 00 02 d2 2a d1 02 15 90 01 04 81 c7 90 01 04 fe ca 89 3d 90 01 04 89 bc 2e 90 01 04 8b 1d 90 01 04 0f b6 ca 2b cb 83 c1 90 01 01 33 ff 83 c6 04 88 54 24 90 01 01 89 0d 90 01 04 89 3d 90 01 04 81 fe 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Hancitor_GT_MTB_2{
	meta:
		description = "Trojan:Win32/Hancitor.GT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 d0 66 89 55 90 01 01 0f b6 05 90 01 04 8b 4d 90 01 01 2b c8 03 4d 90 01 01 88 0d 90 01 04 0f b7 55 90 01 01 03 15 90 01 04 8b 45 90 01 01 8d 8c 10 90 01 04 03 0d 90 01 04 89 0d 90 01 04 0f b6 15 90 01 04 8b 45 90 01 01 8d 8c 10 90 01 04 88 0d 90 01 04 ff 55 90 00 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}