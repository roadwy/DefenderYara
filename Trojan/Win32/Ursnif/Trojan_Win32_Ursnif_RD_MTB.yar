
rule Trojan_Win32_Ursnif_RD_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b c6 99 8b f0 33 c0 3b d0 8b 90 01 03 89 90 01 03 89 90 00 } //1
		$a_02_1 = {8a c2 6b d2 90 01 01 02 c3 04 90 01 01 0f b6 d8 03 da 8a 4c 24 90 01 01 83 c5 90 01 01 02 cb 83 6c 24 90 01 01 90 01 01 89 6c 24 90 00 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}