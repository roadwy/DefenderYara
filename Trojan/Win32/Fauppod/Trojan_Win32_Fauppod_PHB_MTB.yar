
rule Trojan_Win32_Fauppod_PHB_MTB{
	meta:
		description = "Trojan:Win32/Fauppod.PHB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 e5 8a 45 0c 8a 4d 08 31 d2 88 d4 88 c5 02 2d ?? ?? ?? ?? 88 2d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 0f b6 c4 5d c3 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}