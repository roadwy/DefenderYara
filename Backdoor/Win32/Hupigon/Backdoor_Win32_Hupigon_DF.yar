
rule Backdoor_Win32_Hupigon_DF{
	meta:
		description = "Backdoor:Win32/Hupigon.DF,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_03_0 = {c7 07 07 00 01 00 57 8b 45 14 8b 00 50 e8 90 01 04 8d 45 f8 50 6a 04 8b 45 0c 50 8b 87 90 01 01 00 00 00 83 c0 08 50 8b 06 50 e8 90 01 04 8b 7d 0c 8b 3f 90 00 } //01 00 
		$a_03_1 = {6a 00 6a 00 6a 00 6a 00 6a 10 e8 90 01 04 e9 c5 00 00 00 6a 00 6a 00 6a 00 6a 5b e8 90 01 04 a1 90 01 04 8b 00 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}