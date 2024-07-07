
rule Trojan_Win32_Rozena_RPY_MTB{
	meta:
		description = "Trojan:Win32/Rozena.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 40 68 00 10 00 00 56 90 e9 } //1
		$a_01_1 = {90 ff d5 89 c3 89 c7 e9 } //1
		$a_01_2 = {ff d0 90 3c 06 e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}
rule Trojan_Win32_Rozena_RPY_MTB_2{
	meta:
		description = "Trojan:Win32/Rozena.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {31 d2 c7 44 24 38 5c 00 00 00 f7 f1 c7 44 24 34 74 00 00 00 c7 44 24 30 6f 00 00 00 c7 44 24 2c 6c 00 00 00 c7 44 24 28 73 00 00 00 c7 44 24 24 6c 00 00 00 c7 44 24 20 69 00 00 00 c7 44 24 1c 61 00 00 00 c7 44 24 18 6d 00 00 00 c7 44 24 14 5c 00 00 00 } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}