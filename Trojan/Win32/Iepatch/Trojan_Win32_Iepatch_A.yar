
rule Trojan_Win32_Iepatch_A{
	meta:
		description = "Trojan:Win32/Iepatch.A,SIGNATURE_TYPE_PEHSTR,06 00 06 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {68 2e 64 6c 6c } //01 00 
		$a_01_1 = {68 6c 00 00 00 68 70 2e 64 6c } //05 00 
		$a_01_2 = {68 6d 33 32 5c 68 79 73 74 65 68 77 73 5c 73 68 69 6e 64 6f 68 43 3a 5c 57 } //00 00 
		$a_01_3 = {00 67 16 00 00 } //ab 07 
	condition:
		any of ($a_*)
 
}