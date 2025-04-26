
rule Trojan_Win32_RedLineStealer_MH_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 45 fc 8b 4d f0 03 c7 8b f7 d3 ee 50 ff 75 f4 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 03 75 e4 e8 ?? ?? ?? ?? 33 f0 89 45 f4 89 75 ec 8b 45 ec 29 45 f8 25 ?? ?? ?? ?? 8b 55 f8 8b c2 8d 4d f4 e8 ?? ?? ?? ?? 8b 75 fc 8b 4d d8 03 f2 c1 ea 05 8d 45 ec 89 55 ec e8 } //1
		$a_00_1 = {c1 e0 04 89 01 c3 } //1
		$a_03_2 = {89 55 fc b8 ?? ?? ?? ?? 01 45 fc 8b 45 fc 8a 04 08 88 04 31 41 3b 0d ?? ?? ?? ?? 72 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}