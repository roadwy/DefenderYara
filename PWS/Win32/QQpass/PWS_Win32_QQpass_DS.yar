
rule PWS_Win32_QQpass_DS{
	meta:
		description = "PWS:Win32/QQpass.DS,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {5c 5c 2e 5c 73 6c 45 6e 75 6d 48 6f 6f 6b 32 00 } //01 00 
		$a_01_1 = {64 72 69 76 65 72 73 5c 64 48 6f 6f 6b 2e 73 79 73 00 } //01 00 
		$a_01_2 = {44 44 35 46 46 45 44 43 2d 38 44 43 37 2d 34 32 30 46 2d 42 39 39 43 2d 37 37 30 44 42 44 45 45 35 37 34 39 } //00 00 
	condition:
		any of ($a_*)
 
}