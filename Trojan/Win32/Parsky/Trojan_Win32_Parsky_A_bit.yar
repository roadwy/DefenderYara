
rule Trojan_Win32_Parsky_A_bit{
	meta:
		description = "Trojan:Win32/Parsky.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 6b 61 73 70 65 72 5c 52 65 6c 65 61 73 65 5c 6b 61 73 70 65 72 2e 70 64 62 } //01 00 
		$a_01_1 = {00 72 6f 6f 74 69 6e 66 6f 23 23 00 } //01 00 
		$a_01_2 = {00 61 67 65 6e 74 43 68 72 6f 6d 65 23 23 23 23 00 } //01 00 
		$a_01_3 = {00 26 61 63 63 3d 37 23 23 23 23 23 00 } //00 00 
	condition:
		any of ($a_*)
 
}