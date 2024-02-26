
rule Trojan_Win32_Zbot_NZ_MTB{
	meta:
		description = "Trojan:Win32/Zbot.NZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 05 00 "
		
	strings :
		$a_03_0 = {8b d1 8d 4a fe 41 8b d1 8b c8 85 d2 75 15 c1 e2 90 01 01 33 c0 41 85 e4 74 04 03 c9 90 00 } //01 00 
		$a_01_1 = {62 4c 6a 41 51 41 5f 2e 74 78 74 } //00 00  bLjAQA_.txt
	condition:
		any of ($a_*)
 
}