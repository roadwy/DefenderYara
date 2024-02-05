
rule Trojan_Win32_Danmec_J{
	meta:
		description = "Trojan:Win32/Danmec.J,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {5f 6d 73 77 69 6e 33 32 2e 62 61 74 00 } //01 00 
		$a_01_1 = {70 73 74 5f 78 33 32 2e 6c 6f 67 00 } //01 00 
		$a_01_2 = {75 73 62 63 74 6c 2e 65 78 65 00 } //01 00 
		$a_01_3 = {3c 73 69 64 3e 25 73 3c 2f 73 69 64 3e 00 } //00 00 
	condition:
		any of ($a_*)
 
}