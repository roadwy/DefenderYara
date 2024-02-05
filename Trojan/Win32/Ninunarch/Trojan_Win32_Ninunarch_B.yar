
rule Trojan_Win32_Ninunarch_B{
	meta:
		description = "Trojan:Win32/Ninunarch.B,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {24 00 00 00 57 00 69 00 6e 00 5a 00 69 00 70 00 2b 00 3a 00 20 00 } //01 00 
		$a_01_1 = {50 61 79 41 72 63 68 69 76 65 } //01 00 
		$a_01_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 7a 00 69 00 70 00 66 00 69 00 6c 00 65 00 7a 00 2e 00 72 00 75 00 2f 00 70 00 61 00 79 00 61 00 72 00 63 00 68 00 2f 00 } //00 00 
	condition:
		any of ($a_*)
 
}