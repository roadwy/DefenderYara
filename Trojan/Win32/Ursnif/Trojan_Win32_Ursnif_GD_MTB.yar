
rule Trojan_Win32_Ursnif_GD_MTB{
	meta:
		description = "Trojan:Win32/Ursnif.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b c1 33 d2 f7 f3 8a 04 32 88 45 ?? 8a 04 37 88 04 32 8a 55 ?? 8b c1 88 14 37 [0-30] c7 44 24 [0-20] 0b c8 c7 44 24 [0-20] b8 ?? ?? ?? ?? 2b c3 03 c8 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}