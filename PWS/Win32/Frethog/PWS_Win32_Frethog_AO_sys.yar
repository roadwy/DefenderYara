
rule PWS_Win32_Frethog_AO_sys{
	meta:
		description = "PWS:Win32/Frethog.AO!sys,SIGNATURE_TYPE_PEHSTR_EXT,10 00 0f 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {81 7d 20 2b e0 22 00 75 47 83 7d 14 04 73 12 c7 06 0d 00 00 c0 c7 46 04 00 00 00 00 e9 } //04 00 
		$a_01_1 = {83 4d d0 ff c7 45 cc 90 9b f7 ff 6a 00 6a 37 ff 75 d0 ff 75 cc 8d 45 d4 50 e8 } //0a 00 
		$a_01_2 = {74 25 8b 75 10 ff 37 8f 06 50 fa 0f 20 c0 25 ff ff fe ff 0f 22 c0 58 89 07 50 0f 20 c0 0d 00 00 01 00 0f 22 c0 fb 58 } //01 00 
		$a_01_3 = {55 8b ec b8 0d 00 00 c0 c9 c2 10 00 } //00 00 
	condition:
		any of ($a_*)
 
}