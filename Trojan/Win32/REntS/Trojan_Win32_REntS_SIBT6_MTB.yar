
rule Trojan_Win32_REntS_SIBT6_MTB{
	meta:
		description = "Trojan:Win32/REntS.SIBT6!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1f 00 15 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f b6 00 83 f0 ?? 8b 4d ?? 03 4d ?? 88 01 } //10
		$a_03_1 = {88 01 8b 45 ?? 03 45 ?? 0f b6 00 83 c0 ?? 8b 4d 90 1b 00 03 4d 90 1b 01 88 01 } //10
		$a_03_2 = {88 01 8b 45 ?? 03 45 ?? 8a 00 2c ?? 8b 4d 90 1b 00 03 4d 90 1b 01 88 01 } //10
		$a_03_3 = {8b 55 08 b9 3a b6 01 00 90 18 8a 02 84 c0 90 18 6b c9 ?? 0f be c0 03 c8 42 8a 02 84 c0 75 ?? 8b c1 } //1
	condition:
		((#a_03_0  & 1)*10+(#a_03_1  & 1)*10+(#a_03_2  & 1)*10+(#a_03_3  & 1)*1) >=21
 
}