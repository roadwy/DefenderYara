
rule Trojan_Win32_Vidar_ASAF_MTB{
	meta:
		description = "Trojan:Win32/Vidar.ASAF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 03 85 ?? ?? ff ff 8a 08 88 0a eb ?? 8b 55 08 03 95 ?? ?? ff ff 0f b6 02 8b 8d ?? ?? ff ff 33 84 8d ?? ?? ff ff 8b 95 ?? ?? ff ff 03 95 ?? ?? ff ff 88 02 e9 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}