
rule Backdoor_Win32_Hupigon_DD{
	meta:
		description = "Backdoor:Win32/Hupigon.DD,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {ba 01 00 00 00 8b 45 f8 8b 08 ff 51 48 8d 55 f8 a1 90 01 04 e8 90 01 04 8b 45 f8 e8 90 01 04 33 c0 5a 90 00 } //01 00 
		$a_03_1 = {50 6a 00 e8 90 01 04 80 7b 50 00 74 23 0f b7 05 90 01 04 50 6a 00 6a 00 a1 90 01 04 e8 90 01 04 50 68 90 01 04 6a 00 e8 90 01 04 33 c0 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}