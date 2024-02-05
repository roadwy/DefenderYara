
rule Trojan_Win32_Totbrick_D{
	meta:
		description = "Trojan:Win32/Totbrick.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 01 00 "
		
	strings :
		$a_01_0 = {66 83 f9 19 77 03 83 c0 20 83 c6 02 c1 c2 07 0f b7 c0 47 33 d0 0f b7 06 66 85 c0 75 d5 } //01 00 
		$a_01_1 = {46 80 3e 23 75 21 8d 46 01 50 e8 } //00 00 
	condition:
		any of ($a_*)
 
}