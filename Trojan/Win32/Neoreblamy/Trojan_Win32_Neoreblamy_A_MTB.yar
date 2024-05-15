
rule Trojan_Win32_Neoreblamy_A_MTB{
	meta:
		description = "Trojan:Win32/Neoreblamy.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {8b 07 8b 48 04 8a 44 39 40 8b 4c 39 38 88 45 } //02 00 
		$a_03_1 = {8b 4d e8 8b 45 90 01 01 89 1c 88 ff 45 e8 39 75 e8 90 00 } //02 00 
		$a_03_2 = {8b c7 8d 4d 90 01 01 33 c6 99 52 50 e8 90 01 04 59 59 83 78 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}