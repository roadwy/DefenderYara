
rule Trojan_Win32_Doina_EC_MTB{
	meta:
		description = "Trojan:Win32/Doina.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {50 54 57 6a 69 67 35 36 7a 4f 43 6a } //01 00 
		$a_01_1 = {4a 71 79 48 30 77 76 50 43 47 77 30 } //01 00 
		$a_01_2 = {43 4b 6a 43 66 6d 4a 54 47 } //01 00 
		$a_01_3 = {53 79 73 74 65 6d 4d 6f 6e 69 74 6f 72 43 74 6c 2e 53 79 73 74 65 6d 4d 6f 6e 69 74 6f 72 } //01 00 
		$a_01_4 = {53 00 69 00 6d 00 53 00 69 00 6d 00 2e 00 76 00 62 00 70 00 } //00 00 
	condition:
		any of ($a_*)
 
}