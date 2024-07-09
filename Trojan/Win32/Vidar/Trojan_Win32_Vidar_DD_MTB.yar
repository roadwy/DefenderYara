
rule Trojan_Win32_Vidar_DD_MTB{
	meta:
		description = "Trojan:Win32/Vidar.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 10 6a 00 e8 ?? ?? ?? ?? 8b 5d c8 03 5d a0 2b d8 6a 00 e8 ?? ?? ?? ?? 03 d8 8b 45 d8 31 18 83 45 ec 04 83 45 d8 04 8b 45 ec 3b 45 d4 0f 82 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Vidar_DD_MTB_2{
	meta:
		description = "Trojan:Win32/Vidar.DD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {01 c8 88 45 ?? 0f b6 45 ?? 0f b6 84 05 ?? ?? ?? ?? 88 45 ?? 8b 55 ?? 8b 45 ?? 01 d0 0f b6 00 32 45 ?? 88 45 ?? 8b 55 ?? 8b 45 ?? 01 c2 0f b6 45 ?? 88 02 83 45 ?? ?? 8b 45 ?? 3b 45 ?? 0f } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}