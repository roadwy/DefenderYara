
rule Constructor_Win32_Zbot_A{
	meta:
		description = "Constructor:Win32/Zbot.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5a 65 75 53 20 42 75 69 6c 64 65 72 } //01 00 
		$a_01_1 = {00 42 41 53 45 43 4f 4e 46 49 47 00 } //01 00 
		$a_01_2 = {47 6c 6f 62 61 6c 5c 25 30 38 58 25 30 38 58 25 30 38 58 } //00 00 
	condition:
		any of ($a_*)
 
}