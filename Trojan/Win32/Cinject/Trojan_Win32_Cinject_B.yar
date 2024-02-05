
rule Trojan_Win32_Cinject_B{
	meta:
		description = "Trojan:Win32/Cinject.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 01 00 "
		
	strings :
		$a_00_0 = {73 74 6f 62 6a 65 63 74 2e 64 6c 6c } //01 00 
		$a_00_1 = {46 39 39 39 33 33 33 } //01 00 
		$a_03_2 = {68 c0 d4 01 00 ff 15 90 01 04 6a 00 6a 02 ff 15 90 01 04 c3 90 00 } //01 00 
		$a_03_3 = {68 ff 00 00 00 6a 42 ff 15 90 01 04 50 ff 15 90 01 04 a3 90 01 04 ff 35 90 01 04 68 ff 00 00 00 ff 15 90 00 } //01 00 
		$a_03_4 = {68 c9 36 00 00 ff 15 90 01 04 68 90 01 04 68 01 01 00 00 ff 15 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}