
rule Trojan_Win32_Reline_RTA_MTB{
	meta:
		description = "Trojan:Win32/Reline.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {29 c2 f7 d8 0f b6 14 11 b9 ?? ?? ?? ?? 88 94 07 ?? ?? ?? ?? b8 1e 92 dd 2e 2b 45 ?? 29 c1 b8 b4 d0 0c 1b 89 4d ?? 3d 4d e0 b1 13 7e } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}