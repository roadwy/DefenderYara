
rule Trojan_Win32_FormBook_L_MTB{
	meta:
		description = "Trojan:Win32/FormBook.L!MTB,SIGNATURE_TYPE_PEHSTR,05 00 05 00 06 00 00 05 00 "
		
	strings :
		$a_01_0 = {81 34 1f 62 95 40 3e } //05 00 
		$a_01_1 = {78 38 31 34 1f c4 aa 3b 44 } //02 00 
		$a_01_2 = {8b 3c 0a 85 c9 } //03 00 
		$a_01_3 = {39 c9 31 3c 08 } //02 00 
		$a_01_4 = {8b 3c 0a f7 c2 } //03 00 
		$a_01_5 = {31 3c 08 81 fa } //00 00 
	condition:
		any of ($a_*)
 
}