
rule Trojan_Win32_LaplasClipper_E_MTB{
	meta:
		description = "Trojan:Win32/LaplasClipper.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 08 00 00 02 00 "
		
	strings :
		$a_01_0 = {8d 1c 0f f2 } //02 00 
		$a_03_1 = {8d 1c 23 f2 90 09 04 00 83 34 24 90 00 } //02 00 
		$a_01_2 = {23 c3 8b c9 } //02 00 
		$a_01_3 = {f7 d0 c1 cb } //02 00 
		$a_01_4 = {8b 1c 24 c1 e6 } //02 00 
		$a_01_5 = {8d 0c 21 0f ba f0 } //02 00 
		$a_01_6 = {8d 1c 23 23 c1 } //02 00 
		$a_01_7 = {89 0c 24 8d 1c 23 } //00 00 
	condition:
		any of ($a_*)
 
}