
rule Trojan_Win64_Sirefef_P{
	meta:
		description = "Trojan:Win64/Sirefef.P,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 54 48 8b f8 49 8b 90 01 01 f3 a4 0f b7 55 14 44 0f b7 4d 06 90 00 } //1
		$a_01_1 = {49 4e 42 52 36 34 2e 64 6c 6c 00 41 63 63 65 70 } //1 义剂㐶搮汬䄀捣灥
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win64_Sirefef_P_2{
	meta:
		description = "Trojan:Win64/Sirefef.P,SIGNATURE_TYPE_ARHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b 4d 54 48 8b f8 49 8b 90 01 01 f3 a4 0f b7 55 14 44 0f b7 4d 06 90 00 } //1
		$a_01_1 = {49 4e 42 52 36 34 2e 64 6c 6c 00 41 63 63 65 70 } //1 义剂㐶搮汬䄀捣灥
	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}