
rule Trojan_Win32_SquirrelWaffle_B{
	meta:
		description = "Trojan:Win32/SquirrelWaffle.B,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 79 70 73 6f 69 73 6f 74 68 65 72 6d 2e 64 6c 6c } //01 00 
		$a_01_1 = {64 6f 69 74 65 64 2e 70 64 62 } //01 00 
		$a_01_2 = {68 65 74 65 72 6f 7a 79 67 6f 75 73 6e 65 73 73 2e 70 64 62 } //01 00 
		$a_01_3 = {6c 61 7a 61 72 65 74 2e 70 64 62 } //00 00 
		$a_01_4 = {00 5d } //04 00 
	condition:
		any of ($a_*)
 
}