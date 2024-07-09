
rule Trojan_Win32_Vidar_RA_MTB{
	meta:
		description = "Trojan:Win32/Vidar.RA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {99 f7 fe 8b 45 ?? 0f be 0c 11 83 e1 ?? 81 e1 ?? ?? ?? ?? 31 c8 88 45 ?? 0f be 45 ?? 0f be 4d ?? 01 c8 88 c2 8b 45 ?? 8b 4d ?? 88 14 08 0f be 75 ?? 8b 45 ?? 8b 4d ?? 0f be 14 08 29 f2 88 14 08 8b 45 ?? 83 c0 01 89 45 ?? e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}