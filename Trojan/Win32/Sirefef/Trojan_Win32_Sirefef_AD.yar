
rule Trojan_Win32_Sirefef_AD{
	meta:
		description = "Trojan:Win32/Sirefef.AD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {00 00 61 00 63 00 74 00 69 00 6f 00 6e 00 63 00 65 00 6e 00 74 00 65 00 72 00 00 00 } //1
		$a_03_1 = {83 c6 14 8b 46 0c 85 c0 75 ?? e9 ?? 00 00 00 8b 5e 10 8b 06 03 5d 08 03 45 08 eb 1d 78 15 8b 55 08 8d 74 11 02 6a 12 bf ?? ?? ?? ?? 59 33 d2 f3 a6 74 11 83 c3 04 83 c0 04 8b 08 85 c9 75 dd } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Sirefef_AD_2{
	meta:
		description = "Trojan:Win32/Sirefef.AD,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {00 00 61 00 63 00 74 00 69 00 6f 00 6e 00 63 00 65 00 6e 00 74 00 65 00 72 00 00 00 } //1
		$a_03_1 = {83 c6 14 8b 46 0c 85 c0 75 ?? e9 ?? 00 00 00 8b 5e 10 8b 06 03 5d 08 03 45 08 eb 1d 78 15 8b 55 08 8d 74 11 02 6a 12 bf ?? ?? ?? ?? 59 33 d2 f3 a6 74 11 83 c3 04 83 c0 04 8b 08 85 c9 75 dd } //1
	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}