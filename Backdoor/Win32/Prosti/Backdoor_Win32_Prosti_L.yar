
rule Backdoor_Win32_Prosti_L{
	meta:
		description = "Backdoor:Win32/Prosti.L,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {6a 06 6a 01 6a 02 e8 90 01 04 89 43 14 66 c7 45 90 01 01 02 00 56 e8 90 01 04 66 89 45 90 01 01 8b 43 04 50 e8 90 00 } //01 00 
		$a_01_1 = {50 68 7e 66 04 80 8b 43 14 50 e8 } //01 00 
		$a_03_2 = {68 7f 66 04 40 8b 43 14 50 e8 90 01 04 40 75 90 01 01 c7 04 24 ff ff ff ff 8b c3 e8 90 01 04 eb 90 01 01 6a 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}