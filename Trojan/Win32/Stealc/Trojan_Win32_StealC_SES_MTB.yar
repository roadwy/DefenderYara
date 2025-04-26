
rule Trojan_Win32_StealC_SES_MTB{
	meta:
		description = "Trojan:Win32/StealC.SES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b f0 8b c6 c1 e0 04 89 75 f0 89 45 fc 8b 45 d4 01 45 fc 8b 4d ?? 03 fe d3 ee 89 7d e4 03 75 d8 8b 45 e4 31 45 fc 81 3d 74 ?? ?? ?? 03 0b 00 00 75 } //1
		$a_03_1 = {31 75 fc 8b 45 fc 29 45 ec 81 45 f4 ?? ?? ?? ?? ff 4d e0 0f 85 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}