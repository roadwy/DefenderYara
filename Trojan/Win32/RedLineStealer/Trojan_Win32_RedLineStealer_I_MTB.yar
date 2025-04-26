
rule Trojan_Win32_RedLineStealer_I_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.I!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 04 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 89 4c 24 ?? 81 f9 ?? ?? ?? ?? 72 ?? 90 09 05 00 03 c2 0f b6 c0 } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}