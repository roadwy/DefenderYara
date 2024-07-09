
rule Trojan_Win32_Cridex_PVS_MTB{
	meta:
		description = "Trojan:Win32/Cridex.PVS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 44 24 10 13 ea 8b f1 89 2d ?? ?? ?? ?? 8b 0d ?? ?? ?? ?? 8b 54 24 14 81 c1 50 0f 27 02 89 0a } //2
	condition:
		((#a_02_0  & 1)*2) >=2
 
}