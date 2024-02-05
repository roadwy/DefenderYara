
rule Virus_Win32_Expiro_gen_F{
	meta:
		description = "Virus:Win32/Expiro.gen!F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {6b 6b 71 76 78 5f 2e 64 6c 6c 00 } //02 00 
		$a_03_1 = {0f be 10 0f be 90 01 01 02 31 ca 88 10 66 ff 45 90 01 01 0f b7 45 90 01 01 0f b7 55 90 01 01 39 d0 7c df 90 00 } //01 00 
		$a_01_2 = {0f b7 49 06 f7 e1 89 85 } //01 00 
		$a_03_3 = {50 8b 38 ff 97 f8 00 00 00 89 90 04 01 02 c3 c6 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}