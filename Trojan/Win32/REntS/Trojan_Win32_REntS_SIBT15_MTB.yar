
rule Trojan_Win32_REntS_SIBT15_MTB{
	meta:
		description = "Trojan:Win32/REntS.SIBT15!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f b6 02 05 ?? ?? ?? ?? 8b 4d ?? 03 4d ?? 88 01 } //1
		$a_03_1 = {88 01 8b 55 ?? 03 55 ?? 8a 02 2c 01 8b 4d 90 1b 00 03 4d 90 1b 01 88 01 } //1
		$a_03_2 = {88 01 8b 55 ?? 03 55 ?? 0f b6 02 35 ?? ?? ?? ?? 8b 4d 90 1b 00 03 4d 90 1b 01 88 01 } //1
		$a_03_3 = {0f be 11 85 d2 74 ?? 8b 45 ?? c1 e0 ?? 03 45 90 1b 01 8b 4d 08 0f be 11 03 c2 89 45 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}