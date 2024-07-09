
rule Trojan_Win32_Zapchast_MB_MTB{
	meta:
		description = "Trojan:Win32/Zapchast.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f0 83 c4 0c 8b 55 ec 8b 4d e8 66 89 0c 02 33 c9 66 89 4c 02 02 8d 14 5d ?? ?? ?? ?? 8b cf e8 ?? ?? ?? ?? 8b 45 f0 89 06 eb ?? 57 56 50 e8 ?? ?? ?? ?? 8b 45 f0 8d 55 f0 8b 4d e8 83 c4 0c 66 89 0c 07 33 c9 66 89 4c 07 02 8b ce e8 ?? ?? ?? ?? 8b 45 08 40 89 45 08 3b 45 0c 0f 85 } //1
		$a_01_1 = {2e 64 65 62 75 67 5f 77 65 61 6b 6e 61 6d 65 73 } //1 .debug_weaknames
		$a_01_2 = {2e 64 65 62 75 67 5f 70 75 62 6e 61 6d 65 73 } //1 .debug_pubnames
		$a_01_3 = {53 6c 65 65 70 } //1 Sleep
		$a_01_4 = {70 00 72 00 6f 00 78 00 69 00 65 00 73 00 2e 00 74 00 78 00 74 00 } //1 proxies.txt
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}