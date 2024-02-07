
rule PWS_Win32_Zakahic_A{
	meta:
		description = "PWS:Win32/Zakahic.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 0a 00 "
		
	strings :
		$a_00_0 = {80 f9 4f 7f 05 80 c1 30 eb 03 80 e9 30 88 0a 42 } //01 00 
		$a_03_1 = {43 49 43 60 90 02 08 5e 34 3c 3c 90 00 } //01 00 
		$a_01_2 = {35 3c 35 3d 35 3e 44 33 3c 39 35 3e 44 5e 35 } //00 00  5<5=5>D3<95>D^5
	condition:
		any of ($a_*)
 
}