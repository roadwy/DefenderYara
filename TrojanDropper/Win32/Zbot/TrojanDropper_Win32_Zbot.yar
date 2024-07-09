
rule TrojanDropper_Win32_Zbot{
	meta:
		description = "TrojanDropper:Win32/Zbot,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {eb 09 8b 55 ?? 83 c2 01 89 55 ?? 83 7d ?? 29 73 1e 8b 45 ?? 0f b6 4c 05 ?? 85 c9 74 10 8b 55 ?? 81 c2 c9 02 00 00 8b 45 ?? 88 54 05 ?? eb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}