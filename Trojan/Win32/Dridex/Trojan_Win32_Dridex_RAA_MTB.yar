
rule Trojan_Win32_Dridex_RAA_MTB{
	meta:
		description = "Trojan:Win32/Dridex.RAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {ba b4 12 00 00 ba bc 01 00 00 a1 ?? ?? ?? ?? a3 ?? ?? ?? ?? eb } //4
	condition:
		((#a_03_0  & 1)*4) >=4
 
}
rule Trojan_Win32_Dridex_RAA_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.RAA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 c4 04 8b 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 03 15 ?? ?? ?? ?? 2b 55 ?? 03 15 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? a1 ?? ?? ?? ?? 2b 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 03 4d ?? 03 0d ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 83 3d ?? ?? ?? ?? 00 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}