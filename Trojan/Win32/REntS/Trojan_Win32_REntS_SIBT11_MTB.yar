
rule Trojan_Win32_REntS_SIBT11_MTB{
	meta:
		description = "Trojan:Win32/REntS.SIBT11!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {88 10 8b 4d ?? 03 4d ?? 0f b6 11 81 c2 ?? ?? ?? ?? 8b 45 90 1b 00 03 45 90 1b 01 88 10 } //1
		$a_03_1 = {88 10 8b 4d ?? 03 4d ?? 8a 11 80 ea ?? 8b 45 90 1b 00 03 45 90 1b 01 88 10 } //1
		$a_03_2 = {88 10 8b 4d ?? 03 4d ?? 0f b6 11 83 f2 ?? 8b 45 90 1b 00 03 45 90 1b 01 88 10 } //1
		$a_03_3 = {8b c8 8d 52 01 c1 e0 ?? 03 c1 0f be cb 8a 1a 03 c1 84 db 75 ?? 8b 4d 08 3b 45 0c 74 13 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}