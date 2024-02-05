
rule Trojan_Win32_Farfli_CI_MTB{
	meta:
		description = "Trojan:Win32/Farfli.CI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {7a 41 50 63 43 90 01 01 4c 2f 5a 30 65 90 01 01 2f 42 66 62 37 41 76 43 90 00 } //01 00 
		$a_03_1 = {30 30 4f 4f 4f 4f 4f 4f 32 66 90 01 01 31 2f 74 76 90 00 } //02 00 
		$a_01_2 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 } //00 00 
	condition:
		any of ($a_*)
 
}