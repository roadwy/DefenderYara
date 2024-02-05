
rule Trojan_Win32_Copak_CF_MTB{
	meta:
		description = "Trojan:Win32/Copak.CF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 02 00 "
		
	strings :
		$a_03_0 = {31 08 81 c7 90 02 04 89 f6 81 c0 01 00 00 00 39 d0 75 da 90 00 } //02 00 
		$a_01_1 = {31 0a 89 df 42 39 c2 75 ed } //02 00 
		$a_01_2 = {42 4f 31 03 81 c3 01 00 00 00 39 f3 75 e1 } //00 00 
	condition:
		any of ($a_*)
 
}