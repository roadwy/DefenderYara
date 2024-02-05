
rule Trojan_Win32_Demtranc_B{
	meta:
		description = "Trojan:Win32/Demtranc.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 01 00 "
		
	strings :
		$a_03_0 = {eb 7f c6 85 90 01 04 2b c6 85 90 01 04 4f c6 85 90 01 04 4b c6 85 90 01 04 20 c6 85 90 01 04 5a c6 85 90 01 04 45 c6 85 90 01 04 53 90 00 } //01 00 
		$a_03_1 = {74 6b c6 85 90 01 04 2b c6 85 90 01 04 4f c6 85 90 01 04 4b c6 85 90 01 04 20 c6 85 90 01 04 53 c6 85 90 01 04 45 c6 85 90 01 04 55 90 00 } //01 00 
		$a_03_2 = {c2 04 00 c6 85 90 01 04 70 c6 85 90 01 04 75 c6 85 90 01 04 74 c6 85 90 01 04 20 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}