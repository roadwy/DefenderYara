
rule Trojan_Win32_TrickBot_GQ_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_02_0 = {61 00 66 c7 90 02 02 73 00 66 c7 90 02 02 77 00 66 c7 90 02 02 68 00 66 c7 90 02 02 6f 00 66 c7 90 02 02 6f 00 66 c7 90 02 02 6b 00 66 c7 90 02 02 2e 00 66 c7 90 02 02 64 00 66 c7 90 02 02 6c 00 66 c7 90 02 02 6c 00 90 00 } //01 00 
		$a_02_1 = {33 d2 5b 8d 0c 90 02 02 8b 90 02 02 f7 90 02 02 8b 44 90 02 02 8a 90 02 02 30 01 46 3b 74 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_TrickBot_GQ_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBot.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {6a 40 68 00 10 00 00 57 6a 00 ff d3 } //01 00 
		$a_81_1 = {5c 44 4c 4c 50 4f 52 54 41 42 4c 45 58 38 36 5c 33 32 5c 52 65 6c 65 61 73 65 5c 64 6c 6c 33 32 73 6d 70 6c 2e 70 64 62 } //01 00 
		$a_81_2 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } //01 00 
		$a_81_3 = {4b 72 61 73 49 6f 64 57 } //01 00 
		$a_81_4 = {61 73 73 62 31 } //01 00 
		$a_81_5 = {69 6d 69 74 34 } //01 00 
		$a_81_6 = {6c 74 72 69 64 70 } //01 00 
		$a_81_7 = {31 2e 64 6c 6c } //00 00 
	condition:
		any of ($a_*)
 
}