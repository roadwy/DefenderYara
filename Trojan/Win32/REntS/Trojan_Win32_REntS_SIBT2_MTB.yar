
rule Trojan_Win32_REntS_SIBT2_MTB{
	meta:
		description = "Trojan:Win32/REntS.SIBT2!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {88 01 8b 45 ?? 03 45 ?? 0f b6 00 83 c0 ?? 8b 4d 90 1b 00 03 4d 90 1b 01 88 01 8b 45 90 1b 00 03 45 90 1b 01 0f b6 00 2d ed 00 00 00 8b 4d 90 1b 00 03 4d 90 1b 01 88 01 90 18 8b 45 90 1b 01 40 89 45 90 1b 01 8b 45 90 1b 01 3b 45 ?? 90 18 8b 45 90 1b 00 ff e0 } //1
		$a_03_1 = {8b 55 08 b9 ?? ?? ?? ?? 90 18 8a 02 84 c0 90 18 6b c9 21 0f be c0 03 c8 42 8a 02 84 c0 75 ?? 8b c1 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}