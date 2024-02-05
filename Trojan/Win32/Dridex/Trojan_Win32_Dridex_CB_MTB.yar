
rule Trojan_Win32_Dridex_CB_MTB{
	meta:
		description = "Trojan:Win32/Dridex.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 02 00 00 0a 00 "
		
	strings :
		$a_03_0 = {8a 0c 37 88 0e 0f b6 1d 90 01 04 83 e8 01 8a ca 2a c8 80 c1 2d 0f b6 c9 83 c6 01 3b 1d 90 01 04 8d 4c 11 90 00 } //05 00 
		$a_01_1 = {6f 77 6e 5c 53 74 6f 72 65 5c 4f 6e 63 65 5c 42 6f 61 74 5c 61 67 72 65 65 5c 4d 65 6e 5c 4d 69 6c 65 5c 57 69 6c 6c 6d 61 67 6e 65 74 2e 70 64 62 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_Win32_Dridex_CB_MTB_2{
	meta:
		description = "Trojan:Win32/Dridex.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 61 76 65 48 67 72 61 73 73 64 65 65 70 4e 48 69 73 } //01 00 
		$a_01_1 = {35 4b 41 73 69 67 6e 73 73 67 6f 64 76 6f 69 64 61 6d 6f 72 6e 69 6e 67 2e } //01 00 
		$a_01_2 = {77 65 72 65 2c 77 70 6c 61 63 65 74 72 65 65 6d 6f 76 65 74 68 48 52 63 61 6e 2e 74 } //01 00 
		$a_01_3 = {66 67 72 65 61 74 65 72 2e 51 64 69 76 69 64 65 64 2e 6d 36 55 32 } //01 00 
		$a_01_4 = {65 66 36 6a 64 61 79 63 72 65 65 70 65 74 68 6d 61 6b 65 56 48 73 75 62 64 75 65 } //01 00 
		$a_01_5 = {4b 37 39 54 68 65 30 } //00 00 
	condition:
		any of ($a_*)
 
}