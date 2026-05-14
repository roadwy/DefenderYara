
rule Trojan_Win32_SalatStealer_MK_MTB{
	meta:
		description = "Trojan:Win32/SalatStealer.MK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,23 00 23 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e1 89 06 89 d8 89 56 08 f7 e1 31 c9 89 c3 8b 46 04 03 5e 08 11 ca 89 56 08 31 d2 f7 f7 81 7e ?? ?? ?? ?? ?? 8b 16 8b 7e 08 0f 44 d1 0f 44 c1 0f 44 f9 0f 44 d9 01 d0 11 cb 11 cf 0f 92 06 6a ?? 5a 39 c2 b8 00 00 00 00 19 d8 b8 00 00 00 00 19 f8 0f b6 06 19 c1 } //35
	condition:
		((#a_03_0  & 1)*35) >=35
 
}