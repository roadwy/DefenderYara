
rule Trojan_Win32_Priteshel_C{
	meta:
		description = "Trojan:Win32/Priteshel.C,SIGNATURE_TYPE_CMDHSTR_EXT,04 00 04 00 08 00 00 01 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 63 00 } //01 00 
		$a_00_1 = {63 00 6d 00 64 00 20 00 2f 00 63 00 } //03 00 
		$a_02_2 = {73 00 63 00 68 00 74 00 61 00 73 00 6b 00 73 00 90 02 0a 2f 00 63 00 72 00 65 00 61 00 74 00 65 00 90 00 } //03 00 
		$a_02_3 = {5c 00 5c 00 5c 00 22 00 74 00 2e 00 90 02 0a 2e 00 63 00 6f 00 6d 00 5c 00 5c 00 5c 00 90 00 } //03 00 
		$a_02_4 = {6d 00 73 00 69 00 65 00 78 00 65 00 63 00 90 02 10 2f 00 69 00 90 02 10 68 00 74 00 74 00 70 00 3a 00 90 00 } //03 00 
		$a_02_5 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 90 02 30 67 00 65 00 74 00 2d 00 77 00 6d 00 69 00 6f 00 62 00 6a 00 65 00 63 00 74 00 90 02 e0 68 00 74 00 74 00 70 00 90 00 } //f6 ff 
		$a_00_6 = {2f 00 63 00 20 00 22 00 73 00 74 00 61 00 72 00 74 00 20 00 68 00 74 00 74 00 70 00 73 00 3a 00 } //f6 ff 
		$a_00_7 = {48 00 79 00 62 00 72 00 69 00 64 00 4d 00 61 00 69 00 6c 00 44 00 72 00 69 00 76 00 65 00 72 00 } //00 00 
	condition:
		any of ($a_*)
 
}