
rule Trojan_Win32_Dridex_GM_MTB{
	meta:
		description = "Trojan:Win32/Dridex.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 45 e4 8b 4d ec 8a 14 01 8b 75 ?? 81 f6 78 29 34 0a 8b 7d ?? 88 14 07 01 f0 8b 75 ?? 39 f0 89 45 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Dridex_GM_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {b6 73 28 ce c6 06 56 [0-28] 72 8a 5c 24 ?? 88 9c 24 ?? ?? ?? ?? c6 44 24 ?? 74 b7 9e 28 cf c6 44 24 ?? 75 88 6c 24 ?? c6 44 24 ?? 6c c6 84 24 ?? ?? ?? ?? 4a 88 74 24 73 88 cd 80 f5 5e } //10
	condition:
		((#a_02_0  & 1)*10) >=10
 
}