
rule Trojan_Win32_Dridex_AFX_MTB{
	meta:
		description = "Trojan:Win32/Dridex.AFX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f b7 c3 3b f8 74 14 66 29 11 8b c2 66 8b 1d ?? ?? ?? ?? 2b c7 83 e8 4e 0f b7 f0 83 e9 02 81 f9 ?? ?? ?? ?? 7f da } //10
		$a_00_1 = {2a c2 2c 4e 0f b6 c0 2b c2 8b 54 24 10 2b c1 8d 4b 04 02 c8 57 8d 7b 5c 88 4c 24 13 } //10
	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*10) >=20
 
}