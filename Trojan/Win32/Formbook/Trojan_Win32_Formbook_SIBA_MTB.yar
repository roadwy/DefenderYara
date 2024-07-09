
rule Trojan_Win32_Formbook_SIBA_MTB{
	meta:
		description = "Trojan:Win32/Formbook.SIBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {0f b6 11 83 f2 ?? 8b 45 ?? 03 45 ?? 88 10 } //1
		$a_03_1 = {88 10 8b 4d ?? 03 4d ?? 0f b6 11 83 c2 ?? 8b 45 90 1b 00 03 45 90 1b 01 88 10 } //1
		$a_03_2 = {88 10 8b 4d ?? 03 4d ?? 8a 11 80 ea ?? 8b 45 90 1b 00 03 45 90 1b 01 88 10 } //1
		$a_03_3 = {83 c2 01 89 55 ?? 8b 45 90 1b 00 3b 45 ?? 90 18 6a 00 8b 4d ?? 51 6a 00 ff 15 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}