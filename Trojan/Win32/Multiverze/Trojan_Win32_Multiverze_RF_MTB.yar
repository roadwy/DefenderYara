
rule Trojan_Win32_Multiverze_RF_MTB{
	meta:
		description = "Trojan:Win32/Multiverze.RF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 06 00 00 05 00 "
		
	strings :
		$a_81_0 = {77 77 77 2e 67 70 6d 63 65 2e 6e 65 74 } //05 00 
		$a_81_1 = {77 77 77 2e 62 6f 6f 62 6c 65 2e 63 6f 6d } //01 00 
		$a_81_2 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } //01 00 
		$a_81_3 = {72 65 67 77 72 69 74 65 } //01 00 
		$a_81_4 = {73 74 61 72 74 75 70 } //01 00 
		$a_81_5 = {48 4b 45 59 5f 43 55 52 52 45 4e 54 5f 55 53 45 52 5c 53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //00 00 
	condition:
		any of ($a_*)
 
}