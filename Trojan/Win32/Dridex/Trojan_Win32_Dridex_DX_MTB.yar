
rule Trojan_Win32_Dridex_DX_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 24 3e 66 c7 44 24 ?? ?? ?? 30 e0 b4 ?? 8a 54 24 ?? 88 44 24 ?? 88 d0 f6 e4 88 44 24 ?? 8b 5c 24 ?? 8a 44 24 ?? 88 04 3b 83 c7 ?? 8b 44 24 ?? 39 c7 8b 44 24 ?? 89 44 24 ?? 89 4c 24 ?? 89 7c 24 ?? 0f 84 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}