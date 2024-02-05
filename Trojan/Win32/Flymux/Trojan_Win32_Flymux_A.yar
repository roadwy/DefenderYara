
rule Trojan_Win32_Flymux_A{
	meta:
		description = "Trojan:Win32/Flymux.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {46 69 6e 64 20 66 6c 79 20 64 6c 6c 00 } //01 00 
		$a_01_1 = {43 34 35 36 30 44 31 32 2d 43 45 32 35 2d 34 41 32 45 2d 41 35 44 34 2d 42 35 30 37 30 46 43 42 45 32 38 32 } //01 00 
		$a_01_2 = {64 6c 6c 6d 75 78 00 } //00 00 
	condition:
		any of ($a_*)
 
}