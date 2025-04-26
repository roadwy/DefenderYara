
rule Trojan_Win32_Zenpak_GZZ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 e5 8a 45 ?? 8a 4d ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? 0f b6 c0 5d c3 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Zenpak_GZZ_MTB_2{
	meta:
		description = "Trojan:Win32/Zenpak.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {83 c4 10 89 45 e8 68 04 00 00 80 6a 00 68 b7 02 42 00 68 01 00 00 00 bb dc 09 00 00 e8 ?? ?? ?? ?? 83 c4 10 89 45 e4 8d 45 fc 50 } //10
	condition:
		((#a_03_0  & 1)*10) >=10
 
}