
rule Trojan_Win32_Ursnif_GD_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c1 33 d2 f7 f3 8a 04 32 88 45 90 01 01 8a 04 37 88 04 32 8a 55 90 01 01 8b c1 88 14 37 90 02 30 c7 44 24 90 02 20 0b c8 c7 44 24 90 02 20 b8 90 01 04 2b c3 03 c8 90 00 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}