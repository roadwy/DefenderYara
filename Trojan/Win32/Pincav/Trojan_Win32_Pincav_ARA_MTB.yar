
rule Trojan_Win32_Pincav_ARA_MTB{
	meta:
		description = "Trojan:Win32/Pincav.ARA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {8a 82 60 12 40 00 83 f0 d8 88 06 46 42 83 fa 26 75 ee } //02 00 
		$a_01_1 = {30 1a 42 89 c8 03 84 24 6d 01 00 00 39 d0 77 f0 } //02 00 
		$a_01_2 = {30 58 ff 40 39 d0 75 f8 } //00 00 
	condition:
		any of ($a_*)
 
}