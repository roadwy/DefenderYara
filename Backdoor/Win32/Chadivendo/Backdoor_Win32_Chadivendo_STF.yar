
rule Backdoor_Win32_Chadivendo_STF{
	meta:
		description = "Backdoor:Win32/Chadivendo.STF,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {80 7c 3e fe 52 75 90 01 01 80 7c 3e fd 49 75 90 01 01 80 7c 3e fc 44 75 90 01 01 80 7c 3e fb 3c 90 00 } //01 00 
		$a_03_1 = {ba 01 01 00 00 66 3b c2 74 90 01 01 ba 01 02 00 00 66 3b c2 74 90 01 01 ba 01 04 00 00 66 3b c2 74 90 01 01 ba 01 08 00 00 66 3b c2 90 00 } //01 00 
		$a_02_2 = {68 74 74 70 3a 2f 2f 25 73 90 02 20 25 30 38 78 2e 74 78 74 90 00 } //00 00 
		$a_00_3 = {5d 04 } //00 00 
	condition:
		any of ($a_*)
 
}