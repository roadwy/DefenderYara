
rule Trojan_Win32_Powemet_F{
	meta:
		description = "Trojan:Win32/Powemet.F,SIGNATURE_TYPE_CMDHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_00_0 = {5c 00 57 00 4d 00 49 00 43 00 2e 00 65 00 78 00 65 00 } //01 00 
		$a_00_1 = {27 00 50 00 52 00 6f 00 63 00 45 00 73 00 73 00 27 00 } //01 00 
		$a_00_2 = {20 00 43 00 72 00 45 00 61 00 74 00 65 00 20 00 } //01 00 
		$a_00_3 = {43 00 6f 00 4e 00 76 00 65 00 52 00 54 00 5d 00 3a 00 3a 00 46 00 52 00 4f 00 4d 00 42 00 61 00 53 00 65 00 36 00 34 00 53 00 54 00 52 00 49 00 6e 00 47 00 28 00 } //01 00 
		$a_00_4 = {24 00 73 00 68 00 45 00 6c 00 6c 00 49 00 44 00 5b 00 31 00 5d 00 2b 00 24 00 73 00 68 00 65 00 6c 00 6c 00 69 00 44 00 5b 00 31 00 33 00 5d 00 2b 00 27 00 78 00 27 00 29 00 } //01 00 
		$a_00_5 = {2e 00 52 00 45 00 41 00 44 00 74 00 6f 00 65 00 4e 00 64 00 28 00 } //00 00 
	condition:
		any of ($a_*)
 
}