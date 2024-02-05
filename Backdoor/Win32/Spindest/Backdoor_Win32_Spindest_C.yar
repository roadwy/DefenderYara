
rule Backdoor_Win32_Spindest_C{
	meta:
		description = "Backdoor:Win32/Spindest.C,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {8a 08 32 ca 02 ca 88 08 40 4e 75 f4 } //01 00 
		$a_01_1 = {c6 45 d8 5c c6 45 d9 63 c6 45 da 6d c6 45 db 64 c6 45 dc 2e c6 45 de 78 c6 45 e0 00 } //01 00 
		$a_01_2 = {25 73 20 53 50 25 64 20 28 42 75 69 6c 64 20 25 64 29 } //00 00 
	condition:
		any of ($a_*)
 
}