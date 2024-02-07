
rule Trojan_Win32_Boaxxe_F{
	meta:
		description = "Trojan:Win32/Boaxxe.F,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {74 09 89 d0 31 07 83 c7 04 e2 f9 } //01 00 
		$a_01_1 = {61 6a 00 68 6f 75 6e 74 } //01 00  橡栀畯瑮
		$a_03_2 = {3d 2e 54 4d 50 0f 85 90 01 04 68 78 41 00 00 90 00 } //02 00 
		$a_01_3 = {8b 86 cc 00 00 00 89 c2 e8 00 00 00 00 58 } //00 00 
	condition:
		any of ($a_*)
 
}