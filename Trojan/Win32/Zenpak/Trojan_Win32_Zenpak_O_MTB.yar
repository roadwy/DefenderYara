
rule Trojan_Win32_Zenpak_O_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.O!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 75 ec 89 34 24 8b 7d f0 89 7c 24 04 89 44 24 08 0f b6 04 15 ?? ?? ?? ?? 89 44 24 0c 89 4d e4 e8 ?? ?? ?? ?? 8b 45 e4 8b 4d f4 39 c8 89 45 e8 75 bb } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}