
rule Trojan_Win32_TrickbotVP_A_MTB{
	meta:
		description = "Trojan:Win32/TrickbotVP.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_81_0 = {76 70 6e 44 6c 6c 20 62 75 69 6c 64 20 25 73 20 25 73 20 73 74 61 72 74 65 64 } //01 00 
		$a_81_1 = {56 50 4e 20 62 72 69 64 67 65 20 66 61 69 6c 75 72 65 } //01 00 
		$a_81_2 = {31 31 3a 34 33 } //01 00 
		$a_81_3 = {76 70 6e 44 6c 6c 2e 64 6c 6c } //01 00 
		$a_81_4 = {57 61 6e 74 52 65 6c 65 61 73 65 } //01 00 
		$a_81_5 = {52 61 73 47 65 74 43 6f 6e 6e 65 63 74 53 74 61 74 75 73 41 } //00 00 
	condition:
		any of ($a_*)
 
}