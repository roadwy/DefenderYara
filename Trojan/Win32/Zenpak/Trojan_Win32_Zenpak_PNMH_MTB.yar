
rule Trojan_Win32_Zenpak_PNMH_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.PNMH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 e5 8a 45 0c 8a 4d 08 8b 15 ?? ?? ?? ?? 88 c4 02 25 ?? ?? ?? ?? 88 25 ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 89 15 ?? ?? ?? ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? b3 23 00 00 0f b6 c4 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}