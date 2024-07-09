
rule Trojan_Win32_REntS_SIBT_MTB{
	meta:
		description = "Trojan:Win32/REntS.SIBT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {70 65 62 6d 6e 71 68 7a 2e 64 6c 6c } //1 pebmnqhz.dll
		$a_03_1 = {88 01 8b 45 ?? 03 45 ?? 8a 00 04 ?? 8b 4d 90 1b 00 03 4d 90 1b 01 88 01 8b 45 90 1b 00 03 45 90 1b 01 0f b6 00 35 ?? ?? ?? ?? 8b 4d 90 1b 00 03 4d 90 1b 01 88 01 8b 45 90 1b 00 03 45 90 1b 01 0f b6 00 05 ?? ?? ?? ?? 8b 4d 90 1b 00 03 4d 90 1b 01 88 01 90 18 8b 45 90 1b 01 40 89 45 90 1b 01 8b 45 90 1b 01 3b 45 ?? 90 18 8b 45 90 1b 00 ff e0 } //1
		$a_03_2 = {8b 55 08 b9 ?? ?? ?? ?? 90 18 8a 02 84 c0 90 18 6b c9 ?? 0f be c0 03 c8 42 8a 02 84 c0 75 ?? 8b c1 } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}