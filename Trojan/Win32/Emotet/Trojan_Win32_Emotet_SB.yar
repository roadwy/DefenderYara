
rule Trojan_Win32_Emotet_SB{
	meta:
		description = "Trojan:Win32/Emotet.SB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {68 00 6e 00 63 00 6f 00 62 00 6a 00 61 00 70 00 69 00 2e 00 64 00 6c 00 6c 00 } //05 00 
		$a_01_1 = {68 77 73 6a 6b 69 73 6c 6f 70 6b 6a 75 6e 68 79 74 67 68 } //01 00 
		$a_01_2 = {50 68 6f 6e 65 42 6f 6f 6b 45 6e 75 6d 4e 75 6d 62 65 72 73 } //01 00 
		$a_01_3 = {50 68 6f 6e 65 42 6f 6f 6b 4c 6f 61 64 } //01 00 
		$a_01_4 = {50 68 6f 6e 65 42 6f 6f 6b 45 6e 75 6d 43 6f 75 6e 74 72 69 65 73 } //01 00 
		$a_01_5 = {50 68 6f 6e 65 42 6f 6f 6b 46 72 65 65 46 69 6c 74 65 72 } //00 00 
	condition:
		any of ($a_*)
 
}