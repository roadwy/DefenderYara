
rule Trojan_Win32_RedLineStealer_MTA_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.MTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {88 04 39 83 3d ?? ?? ?? ?? 44 75 90 0a 1f 00 a1 ?? ?? ?? ?? 8a 84 38 3b 2d 0b 00 8b 0d } //1
		$a_03_1 = {03 c7 50 89 45 f8 8b c7 c1 e0 04 03 85 ?? ?? ?? ?? 50 e8 6a fe ff ff 50 89 85 ?? ?? ?? ?? 8b c7 c1 e8 05 03 85 ?? ?? ?? ?? 50 8d 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}