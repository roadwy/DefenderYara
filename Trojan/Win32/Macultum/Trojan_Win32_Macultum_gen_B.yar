
rule Trojan_Win32_Macultum_gen_B{
	meta:
		description = "Trojan:Win32/Macultum.gen!B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {75 05 89 7d e8 eb 0f 33 c0 40 89 45 e8 83 f9 04 74 09 3b c8 74 05 ff 46 44 } //02 00 
		$a_03_1 = {74 36 6a 00 6a 04 8b ce e8 90 01 04 e8 90 01 04 68 30 75 00 00 ff 35 90 01 04 ff 15 90 01 04 85 c0 75 e6 90 00 } //01 00 
		$a_01_2 = {77 62 74 5f 6d 65 64 69 61 2f 6d 75 74 75 61 6c 70 75 62 6c 69 63 } //00 00  wbt_media/mutualpublic
	condition:
		any of ($a_*)
 
}