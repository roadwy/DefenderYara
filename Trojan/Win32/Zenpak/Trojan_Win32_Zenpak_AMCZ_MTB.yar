
rule Trojan_Win32_Zenpak_AMCZ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.AMCZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {55 89 e5 8a 45 0c 8a 4d 08 31 d2 88 d4 8b 15 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 88 c5 02 2d ?? ?? ?? ?? 88 2d ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 0f b6 c4 5d c3 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}