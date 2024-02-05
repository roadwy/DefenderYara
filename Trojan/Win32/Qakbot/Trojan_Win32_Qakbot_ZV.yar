
rule Trojan_Win32_Qakbot_ZV{
	meta:
		description = "Trojan:Win32/Qakbot.ZV,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 06 00 00 01 00 "
		
	strings :
		$a_01_0 = {f1 d5 00 fa 4c 62 cc f4 0f 0b } //05 00 
		$a_01_1 = {d0 07 00 00 } //05 00 
		$a_03_2 = {a0 0f 00 00 90 09 02 00 81 90 00 } //05 00 
		$a_03_3 = {d0 07 00 00 90 09 02 00 81 90 00 } //05 00 
		$a_03_4 = {70 17 00 00 90 09 02 00 81 90 00 } //05 00 
		$a_03_5 = {f7 04 84 ff 90 09 04 00 c7 45 90 01 01 00 90 00 } //01 00 
		$a_00_6 = {5d 04 00 00 c5 00 05 80 5c 20 00 00 c6 00 05 80 00 00 01 00 08 00 0a 00 ac } //21 54 
	condition:
		any of ($a_*)
 
}