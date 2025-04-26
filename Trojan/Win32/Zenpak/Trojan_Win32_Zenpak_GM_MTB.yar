
rule Trojan_Win32_Zenpak_GM_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 d3 03 c2 [0-30] 8b 85 ?? ?? ?? ?? 40 83 c4 ?? 89 85 ?? ?? ?? ?? 0f b6 94 15 [0-20] 30 50 ?? 83 7d [0-20] 0f 85 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}