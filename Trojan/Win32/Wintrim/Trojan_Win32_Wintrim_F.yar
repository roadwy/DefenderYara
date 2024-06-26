
rule Trojan_Win32_Wintrim_F{
	meta:
		description = "Trojan:Win32/Wintrim.F,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 04 00 00 0a 00 "
		
	strings :
		$a_00_0 = {4d 43 76 32 44 4c 4c 2e 64 6c 6c 00 53 74 61 72 74 4d 43 } //05 00 
		$a_02_1 = {45 58 43 45 50 54 49 4f 4e 90 02 0a 41 43 4b 4e 4f 57 4c 45 44 90 02 10 5f 4c 49 53 54 53 90 02 32 3c 49 44 90 02 07 61 63 6b 6e 6f 77 90 00 } //05 00 
		$a_02_2 = {65 6e 63 6f 64 69 6e 67 90 02 0a 38 38 35 39 90 02 22 43 6f 6d 70 90 02 0e 49 6e 73 74 61 90 00 } //05 00 
		$a_02_3 = {6d 41 6e 64 4c 6f 61 64 90 02 25 3a 3a 90 02 41 70 6d 63 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}