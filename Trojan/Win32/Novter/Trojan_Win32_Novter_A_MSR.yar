
rule Trojan_Win32_Novter_A_MSR{
	meta:
		description = "Trojan:Win32/Novter.A!MSR,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {7b 22 61 63 63 6c 22 3a 5b 22 90 02 05 3a 2f 2f 90 02 03 2e 90 02 03 2e 90 02 03 2e 90 02 03 3a 90 02 03 2f 22 2c 22 90 02 05 3a 2f 2f 90 02 03 2e 90 02 03 2e 90 02 03 2e 90 02 03 3a 90 02 03 2f 22 2c 90 00 } //01 00 
		$a_00_1 = {44 69 73 61 62 6c 65 52 65 61 6c 74 69 6d 65 4d 6f 6e 69 74 6f 72 69 6e 67 } //01 00 
		$a_00_2 = {6b 69 6c 6c 61 6c 6c } //01 00 
		$a_00_3 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e } //00 00 
	condition:
		any of ($a_*)
 
}