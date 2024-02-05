
rule Trojan_Win32_Tracur_BB{
	meta:
		description = "Trojan:Win32/Tracur.BB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {69 f2 04 04 00 00 8b 45 fc 8b 40 10 80 7c f0 10 00 75 05 89 55 f0 eb 28 } //01 00 
		$a_00_1 = {69 c3 04 04 00 00 8b 7d fc 8b 7f 10 dd 44 c7 20 8b 45 fc 8b 40 10 dc 5c f0 20 df e0 } //01 00 
		$a_01_2 = {89 55 fc 89 45 f8 60 ff 75 fc 8b 45 f8 83 c0 18 50 89 c1 e8 08 00 00 00 83 c4 08 e9 a9 00 00 00 } //00 00 
		$a_00_3 = {80 } //10 00 
	condition:
		any of ($a_*)
 
}