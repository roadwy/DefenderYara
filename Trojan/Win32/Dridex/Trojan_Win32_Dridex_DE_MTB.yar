
rule Trojan_Win32_Dridex_DE_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 4c 24 50 83 f8 6a 89 44 24 24 0f 84 ?? ?? ?? ?? e9 ?? ?? ?? ?? 8b 44 24 30 8d 65 fc 5e 5d c3 a1 ?? ?? ?? ?? 0f b6 00 3d b8 00 00 00 0f 84 } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Dridex_DE_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.DE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 16 01 d1 35 ?? ?? ?? ?? 89 45 ?? 89 c8 99 8b 4d ?? f7 f9 8b 75 ?? 89 16 8b 55 ?? 8b 0a 8b 55 ?? 8b 12 0f b6 0c 0a 8b 16 8b 75 ?? 8b 36 0f b6 14 16 31 d1 88 cb 8b 4d ?? 8b 11 8b 75 ?? 8b 0e 88 1c 11 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}