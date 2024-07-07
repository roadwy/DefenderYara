
rule Trojan_Win32_Ursnif_AY_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.AY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b7 ea f7 ed c1 fa 90 01 01 8b da c1 eb 90 01 01 03 da 90 08 30 00 0f b6 c1 83 c0 90 01 01 0f b7 f7 03 35 90 01 04 03 c5 99 89 44 24 90 01 01 a3 90 01 04 8b c2 90 00 } //1
		$a_02_1 = {2b c5 83 c0 90 01 01 99 a3 90 01 04 89 15 90 01 04 8b 44 24 90 01 01 81 c6 90 01 04 8b 6c 24 90 01 01 2b c3 89 35 90 01 04 8d 14 40 89 75 00 c1 e2 05 83 c5 04 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}