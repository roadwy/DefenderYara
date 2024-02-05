
rule Trojan_Win32_Astaroth_B{
	meta:
		description = "Trojan:Win32/Astaroth.B,SIGNATURE_TYPE_CMDHSTR_EXT,10 00 10 00 05 00 00 05 00 "
		
	strings :
		$a_00_0 = {63 00 6d 00 64 00 } //0a 00 
		$a_02_1 = {74 00 79 00 70 00 65 00 20 00 90 02 28 2e 00 64 00 6c 00 6c 00 20 00 90 02 28 2e 00 64 00 6c 00 6c 00 90 00 } //01 00 
		$a_00_2 = {6d 00 6f 00 7a 00 63 00 72 00 74 00 31 00 39 00 2e 00 64 00 6c 00 6c 00 } //01 00 
		$a_00_3 = {6d 00 6f 00 7a 00 73 00 71 00 6c 00 69 00 74 00 65 00 33 00 2e 00 64 00 6c 00 6c 00 } //01 00 
		$a_00_4 = {73 00 71 00 6c 00 69 00 74 00 65 00 33 00 2e 00 64 00 6c 00 6c 00 } //00 00 
	condition:
		any of ($a_*)
 
}