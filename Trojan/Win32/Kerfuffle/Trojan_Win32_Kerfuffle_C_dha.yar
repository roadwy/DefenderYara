
rule Trojan_Win32_Kerfuffle_C_dha{
	meta:
		description = "Trojan:Win32/Kerfuffle.C!dha,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 6c 6c 5f 77 57 69 6e 4d 61 69 6e } //01 00 
		$a_01_1 = {49 6e 73 74 4c 73 70 44 6c 6c 2e 64 6c 6c } //01 00 
		$a_01_2 = {49 6d 6d 57 69 6e 33 32 2e 69 6d 65 } //01 00 
		$a_01_3 = {6d 73 64 74 63 36 34 2e 73 79 73 } //02 00 
		$a_01_4 = {63 6f 6e 69 6d 65 31 2e 64 61 74 } //01 00 
		$a_01_5 = {57 69 6e 41 64 76 2e 62 61 6b } //02 00 
		$a_01_6 = {54 65 6d 70 5c 00 00 00 6b 65 6c 6c 2e 64 61 74 } //02 00 
		$a_01_7 = {54 65 6d 70 5c 00 00 00 77 6e 64 70 77 64 } //00 00 
	condition:
		any of ($a_*)
 
}