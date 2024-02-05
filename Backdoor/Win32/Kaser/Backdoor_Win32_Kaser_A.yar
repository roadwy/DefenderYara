
rule Backdoor_Win32_Kaser_A{
	meta:
		description = "Backdoor:Win32/Kaser.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {53 61 6b 65 72 45 76 65 6e 74 } //05 00 
		$a_01_1 = {4a 75 73 74 54 65 6d 70 46 75 6e } //01 00 
		$a_01_2 = {66 89 55 f8 c6 45 e8 47 c6 45 eb 43 c6 45 f2 50 } //01 00 
		$a_01_3 = {66 89 55 ec c6 45 dc 47 c6 45 df 43 c6 45 e6 50 } //00 00 
		$a_00_4 = {5d 04 00 00 d3 0b 03 80 5c 23 } //00 00 
	condition:
		any of ($a_*)
 
}