
rule Trojan_Win32_Redaman_B{
	meta:
		description = "Trojan:Win32/Redaman.B,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 03 00 "
		
	strings :
		$a_02_0 = {ff 10 50 8f 05 90 01 04 8d 90 01 05 c7 90 01 01 48 65 61 70 66 c7 90 01 01 04 43 72 90 02 01 c7 90 01 01 06 65 61 90 02 03 50 ff 35 90 0a 38 00 8d 05 90 00 } //01 00 
		$a_00_1 = {4c 69 62 72 61 72 79 41 } //01 00 
		$a_00_2 = {70 72 69 74 65 50 72 6f 5f 5f 5f 5f 5f 65 5f 6f 72 79 } //00 00 
		$a_00_3 = {5d 04 00 } //00 67 
	condition:
		any of ($a_*)
 
}