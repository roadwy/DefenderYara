
rule Trojan_Win32_Azorult_RPY_MTB{
	meta:
		description = "Trojan:Win32/Azorult.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c1 c1 e0 04 03 c2 8b d1 03 4c 24 08 c1 ea 05 03 54 24 04 33 c2 33 c1 c3 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}
rule Trojan_Win32_Azorult_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/Azorult.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {56 8b 30 8b 40 04 89 45 f8 8b 45 0c 8b 08 89 4d e0 8b 48 04 89 4d e8 8b 48 08 8b 40 0c 57 } //1
		$a_01_1 = {8b 45 08 89 78 04 5f 89 30 5e 5b c9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}
rule Trojan_Win32_Azorult_RPY_MTB_3{
	meta:
		description = "Trojan:Win32/Azorult.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {01 7c 24 10 89 6c 24 18 8b 44 24 24 01 44 24 18 8b 44 24 38 90 01 44 24 18 8b 44 24 18 89 44 24 20 8b 4c 24 1c 8b 44 24 20 8b d6 d3 ea 8b 4c 24 10 50 51 03 d3 89 54 24 1c } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}