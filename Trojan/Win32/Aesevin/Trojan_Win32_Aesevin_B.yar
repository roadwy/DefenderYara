
rule Trojan_Win32_Aesevin_B{
	meta:
		description = "Trojan:Win32/Aesevin.B,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 61 37 2e 69 6e 69 00 30 00 6e 00 67 00 } //01 00 
		$a_01_1 = {47 30 30 47 4c 45 00 } //01 00 
		$a_01_2 = {62 6f 64 79 00 69 6e 6e 65 72 48 54 4d 4c 00 } //00 00 
	condition:
		any of ($a_*)
 
}