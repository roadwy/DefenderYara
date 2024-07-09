
rule Trojan_Win32_Shelm_M_MTB{
	meta:
		description = "Trojan:Win32/Shelm.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 c8 88 84 3d ?? ?? ?? ?? 0f b6 84 35 ?? ?? ?? ?? 03 c8 0f b6 c1 8b 8d d8 ?? ?? ?? 0f b6 84 05 ?? ?? ?? ?? 32 44 13 ?? 88 04 0a 42 81 fa } //2
	condition:
		((#a_03_0  & 1)*2) >=2
 
}