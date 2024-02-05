
rule Trojan_Win32_Convagent_EN_MTB{
	meta:
		description = "Trojan:Win32/Convagent.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 65 6c 78 73 79 75 31 21 } //01 00 
		$a_01_1 = {53 48 65 3b 21 } //01 00 
		$a_01_2 = {44 6f 65 73 20 69 74 20 77 6f 72 6b 21 4c } //01 00 
		$a_01_3 = {59 48 55 41 73 67 79 75 } //01 00 
		$a_01_4 = {57 6b 75 78 7a 67 73 58 7b 74 7b 6a 67 75 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Convagent_EN_MTB_2{
	meta:
		description = "Trojan:Win32/Convagent.EN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {73 76 67 73 6a 69 67 6a 34 39 68 6f 69 68 6a 72 69 } //01 00 
		$a_01_1 = {73 6f 67 69 6a 73 34 38 39 73 68 35 72 6a 69 68 6f 20 6a 68 20 69 20 2b 20 69 } //01 00 
		$a_01_2 = {66 6f 72 6b 38 2e 64 6c 6c } //01 00 
		$a_01_3 = {56 65 72 69 66 79 56 65 72 73 69 6f 6e 49 6e 66 6f 41 } //01 00 
		$a_01_4 = {69 41 54 35 42 69 6b 79 67 77 49 34 4a 37 63 56 4b 41 71 30 6d 57 64 49 } //00 00 
	condition:
		any of ($a_*)
 
}