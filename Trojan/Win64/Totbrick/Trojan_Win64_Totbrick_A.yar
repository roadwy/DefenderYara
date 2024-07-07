
rule Trojan_Win64_Totbrick_A{
	meta:
		description = "Trojan:Win64/Totbrick.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {66 83 c0 41 66 89 04 4b 48 8b 85 98 00 00 00 66 83 3c 43 46 } //1
		$a_01_1 = {80 3b 2a 75 06 48 ff c3 48 8b eb 0f b6 03 38 07 74 05 48 8b dd eb } //1
		$a_01_2 = {66 c7 44 24 40 48 b9 66 c7 45 81 48 b8 66 c7 45 8b ff e0 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}