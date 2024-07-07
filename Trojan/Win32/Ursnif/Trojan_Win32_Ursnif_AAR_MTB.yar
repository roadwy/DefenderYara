
rule Trojan_Win32_Ursnif_AAR_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AAR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 d2 2b c5 1b 54 24 90 01 01 8b e8 89 54 24 90 01 01 eb 90 0a 30 00 83 f8 90 01 01 74 90 01 01 3d 90 01 04 74 90 01 01 83 c0 90 00 } //1
		$a_02_1 = {8b cd 6b c9 90 01 01 83 44 24 90 01 02 2b f9 8b 0d 90 01 04 03 f7 89 35 90 01 04 89 08 a1 90 01 04 8b 15 90 01 04 8b c8 6b c9 90 01 01 03 d1 81 7c 24 90 01 05 8d 44 10 90 01 01 89 0d 90 01 04 a3 90 01 04 0f 82 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}