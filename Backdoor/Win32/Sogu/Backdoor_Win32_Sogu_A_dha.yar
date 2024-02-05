
rule Backdoor_Win32_Sogu_A_dha{
	meta:
		description = "Backdoor:Win32/Sogu.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {83 7d fc 5a 7e 09 b8 cc cc cc cc ff d0 } //01 00 
		$a_03_1 = {0f b6 02 0f b6 4d 90 01 01 0f b6 55 90 01 01 03 ca 0f b6 55 90 01 01 03 ca 0f b6 55 90 01 01 03 ca 33 c1 90 00 } //01 00 
		$a_01_2 = {53 00 61 00 66 00 65 00 53 00 76 00 63 00 2e 00 65 00 78 00 65 00 } //00 00 
	condition:
		any of ($a_*)
 
}