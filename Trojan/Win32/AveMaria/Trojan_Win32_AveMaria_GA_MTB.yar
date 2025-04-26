
rule Trojan_Win32_AveMaria_GA_MTB{
	meta:
		description = "Trojan:Win32/AveMaria.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 0c d0 f7 d1 8b 55 ?? 03 55 ?? 88 0a 90 13 [0-20] 8b 45 ?? 83 c0 ?? 89 45 ?? 8b 4d ?? 83 e9 ?? 39 4d [0-25] 8b 55 ?? 83 ea ?? 2b 55 ?? 8b 85 } //1
		$a_02_1 = {0f be 02 8b 8d [0-20] 0f be 54 0d ?? 33 c2 8b 4d ?? 03 4d ?? 88 01 90 13 [0-20] 8b 45 ?? 83 c0 ?? 89 45 ?? 8b 4d ?? 3b 8d [0-20] 8b 45 [0-30] 89 95 [0-20] 8b 55 ?? 03 55 } //1
	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}