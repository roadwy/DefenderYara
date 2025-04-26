
rule Trojan_Win32_Zloader_SIBG_MTB{
	meta:
		description = "Trojan:Win32/Zloader.SIBG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 11 88 55 ?? [0-a0] 0f b6 4d 90 1b 00 2b 8d ?? ?? ?? ?? 88 4d 90 1b 00 [0-f0] 8a 45 90 1b 00 8a 8d 90 1b 03 d2 c0 88 45 90 1b 00 [0-70] 8b 85 ?? ?? ?? ?? 8a 4d 90 1b 00 88 08 [0-c0] 8b 85 ?? ?? ?? ?? 83 c0 ?? 89 85 90 1b 0d [0-70] 8b 85 90 1b 0a 83 c0 ?? 89 85 90 1b 0a [0-80] 8b 8d 90 1b 03 c1 c1 ?? 89 8d 90 1b 03 [0-e0] 69 95 90 1b 03 ?? ?? ?? ?? 89 95 90 1b 03 [0-a0] 8b 85 ?? ?? ?? ?? 05 a7 22 00 00 89 85 90 1b 1d [0-c0] 90 18 8b 95 90 1b 1d 3b 95 a8 fe ff ff 0f 8d ?? ?? ?? ?? [0-a0] 8b 8d 90 1b 0d 8a 11 } //1
	condition:
		((#a_02_0  & 1)*1) >=1
 
}