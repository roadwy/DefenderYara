
rule PWS_Win32_Bissldr_A{
	meta:
		description = "PWS:Win32/Bissldr.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {62 73 73 73 74 65 61 6c 65 72 5f 6c 6f 61 64 65 72 } //01 00 
		$a_01_1 = {50 41 53 53 57 4f 52 44 53 5f 49 45 58 50 } //01 00 
		$a_01_2 = {50 43 5f 49 4e 46 4f 5f 47 45 54 } //00 00 
	condition:
		any of ($a_*)
 
}