
rule Trojan_Win32_BumbleBee_AB_MTB{
	meta:
		description = "Trojan:Win32/BumbleBee.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_01_0 = {76 77 76 30 34 35 64 6f 33 38 2e 64 6c 6c } //01 00 
		$a_01_1 = {43 53 6c 53 62 44 34 38 } //01 00 
		$a_01_2 = {49 54 65 33 30 35 } //01 00 
		$a_01_3 = {41 70 70 53 74 61 72 74 } //00 00 
	condition:
		any of ($a_*)
 
}