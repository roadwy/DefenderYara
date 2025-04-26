
rule Trojan_Win32_Zenpak_DED_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.DED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d3 2b d0 83 ea 09 0f b7 d2 0f b6 f1 0f b7 ea 2b ee 8d 5c 2b 2c 8b f3 0f af f2 2b f0 0f b7 ee 89 54 24 10 89 1d ?? ?? ?? ?? 89 6c 24 10 8b 15 ?? ?? ?? ?? 8b c7 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}