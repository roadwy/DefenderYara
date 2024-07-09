
rule Trojan_Win32_RedLineStealer_DI_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.DI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 03 45 f8 8a 08 88 4d fe 0f b6 4d fe 8b 45 f8 33 d2 f7 75 10 0f b6 92 ?? ?? ?? ?? 33 ca 88 4d ff 8b 45 08 03 45 f8 8a 08 88 4d fd } //1
		$a_01_1 = {8b 55 08 03 55 f8 88 0a 8a 45 fd 88 45 fc 0f b6 4d fc 8b 55 08 03 55 f8 0f b6 02 2b c1 8b 4d 08 03 4d f8 88 01 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}