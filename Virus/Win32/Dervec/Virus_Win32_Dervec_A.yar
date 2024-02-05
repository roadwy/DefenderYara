
rule Virus_Win32_Dervec_A{
	meta:
		description = "Virus:Win32/Dervec.A,SIGNATURE_TYPE_PEHSTR_EXT,65 00 65 00 03 00 00 64 00 "
		
	strings :
		$a_03_0 = {6a 17 68 83 00 00 00 56 ff 15 90 01 04 89 45 90 01 01 3b c6 74 75 90 00 } //01 00 
		$a_01_1 = {66 c7 04 3e cc cc 66 c7 44 3e 02 cc 60 c6 44 3e 04 68 } //01 00 
		$a_01_2 = {83 f8 03 74 1f 83 f8 02 74 1a fe c3 80 fb 47 7e } //00 00 
	condition:
		any of ($a_*)
 
}