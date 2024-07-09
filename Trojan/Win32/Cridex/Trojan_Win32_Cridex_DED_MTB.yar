
rule Trojan_Win32_Cridex_DED_MTB{
	meta:
		description = "Trojan:Win32/Cridex.DED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b7 c8 8d 7f 04 8b c1 2b 44 24 14 05 ?? ?? ?? ?? 03 c6 03 d0 8b c3 2b c5 83 c0 b1 03 f0 8b 47 fc 8d 6a 51 05 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 47 fc } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}