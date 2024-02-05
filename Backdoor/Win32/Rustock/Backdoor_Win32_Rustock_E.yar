
rule Backdoor_Win32_Rustock_E{
	meta:
		description = "Backdoor:Win32/Rustock.E,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {c7 45 f4 a2 a9 00 00 81 7d f4 bb 00 00 00 7f 20 c7 45 ec 65 2f 00 00 c7 45 f8 56 41 08 f7 } //01 00 
		$a_01_1 = {0f b7 11 81 fa 4d 5a 00 00 74 5f 8b 45 f8 2d 00 10 00 00 89 45 f8 c7 45 e8 47 00 00 00 c7 45 f0 80 00 00 00 } //00 00 
	condition:
		any of ($a_*)
 
}