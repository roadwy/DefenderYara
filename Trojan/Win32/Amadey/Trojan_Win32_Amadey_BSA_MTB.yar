
rule Trojan_Win32_Amadey_BSA_MTB{
	meta:
		description = "Trojan:Win32/Amadey.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {be 58 9a d7 7f 4e 81 f6 76 ab 9f 6d 81 ee 74 7c ab 58 81 c6 77 86 3f 67 81 ce da 03 be 6b 81 ee fa 3b fe 6b 01 f7 5e 83 ef 04 87 3c 24 } //10
	condition:
		((#a_01_0  & 1)*10) >=10
 
}
rule Trojan_Win32_Amadey_BSA_MTB_2{
	meta:
		description = "Trojan:Win32/Amadey.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 08 00 00 "
		
	strings :
		$a_01_0 = {eb 08 0f dc 2d 00 00 00 00 00 e9 } //1
		$a_01_1 = {eb 08 0f 24 2e 00 00 00 00 00 e9 } //1
		$a_01_2 = {eb 08 0f 22 2e 00 00 00 00 00 e9 } //1
		$a_01_3 = {eb 08 0f 48 2d 00 00 00 00 00 e9 } //1
		$a_01_4 = {eb 08 0f 28 2d 00 00 00 00 00 e9 } //1
		$a_01_5 = {eb 08 0f fc 2c 00 00 00 00 00 e9 } //1
		$a_01_6 = {eb 08 0f ee 2c 00 00 00 00 00 e9 } //1
		$a_01_7 = {eb 08 0f 4a 2b 00 00 00 00 00 e9 } //1
	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=1
 
}