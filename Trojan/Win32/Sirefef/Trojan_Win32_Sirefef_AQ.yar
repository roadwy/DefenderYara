
rule Trojan_Win32_Sirefef_AQ{
	meta:
		description = "Trojan:Win32/Sirefef.AQ,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 83 7e 0e 2e 75 07 66 83 7e 0c 2e 74 ?? 66 8b 46 08 } //1
		$a_03_1 = {83 fa 0c 75 2d 8b 50 06 33 d1 89 15 ?? ?? ?? ?? 8b d6 66 33 50 0a 66 89 15 ?? ?? ?? ?? 8b 10 33 d1 89 15 ?? ?? ?? ?? 66 33 70 04 66 89 35 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Sirefef_AQ_2{
	meta:
		description = "Trojan:Win32/Sirefef.AQ,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 83 7e 0e 2e 75 07 66 83 7e 0c 2e 74 ?? 66 8b 46 08 } //1
		$a_03_1 = {83 fa 0c 75 2d 8b 50 06 33 d1 89 15 ?? ?? ?? ?? 8b d6 66 33 50 0a 66 89 15 ?? ?? ?? ?? 8b 10 33 d1 89 15 ?? ?? ?? ?? 66 33 70 04 66 89 35 } //1
	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}