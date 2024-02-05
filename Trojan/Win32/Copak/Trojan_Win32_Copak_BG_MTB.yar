
rule Trojan_Win32_Copak_BG_MTB{
	meta:
		description = "Trojan:Win32/Copak.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 04 00 00 02 00 "
		
	strings :
		$a_03_0 = {21 d2 4f 31 18 ba 90 02 04 40 29 d2 39 c8 75 e3 90 00 } //02 00 
		$a_03_1 = {29 da 31 38 bb 90 02 04 40 42 39 c8 75 e1 90 00 } //03 00 
		$a_01_2 = {01 d2 43 81 c2 01 00 00 00 ba 5e 4e b1 24 81 fb e2 4d 00 01 75 b1 } //03 00 
		$a_01_3 = {01 f3 81 c0 01 00 00 00 09 f6 81 f8 84 c9 00 01 75 b6 } //00 00 
	condition:
		any of ($a_*)
 
}