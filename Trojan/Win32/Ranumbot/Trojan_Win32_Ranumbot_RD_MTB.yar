
rule Trojan_Win32_Ranumbot_RD_MTB{
	meta:
		description = "Trojan:Win32/Ranumbot.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 04 00 00 01 00 "
		
	strings :
		$a_02_0 = {33 d0 89 45 90 01 01 89 95 90 01 04 89 3d 90 01 04 8b 85 90 01 04 29 45 90 01 01 81 3d 90 01 04 d5 01 00 00 90 00 } //05 00 
		$a_02_1 = {c1 e8 05 89 45 90 01 01 c7 05 90 01 04 2e ce 50 91 8b 85 90 01 04 01 45 90 01 01 81 3d 90 01 04 12 09 00 00 75 90 00 } //05 00 
		$a_02_2 = {8d 0c 02 e8 90 01 04 30 01 42 3b 54 24 90 01 01 7c 90 00 } //01 00 
		$a_02_3 = {69 c0 fd 43 03 00 a3 90 01 04 81 45 90 01 01 c3 9e 26 00 a1 90 01 04 03 45 90 01 01 83 65 90 01 02 a3 90 01 04 81 45 90 01 01 ff 7f 00 00 c1 e8 10 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}