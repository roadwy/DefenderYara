
rule Trojan_Win32_Tainp_A_MTB{
	meta:
		description = "Trojan:Win32/Tainp.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 02 00 "
		
	strings :
		$a_01_0 = {03 03 8a 00 89 f6 } //02 00 
		$a_03_1 = {03 13 88 02 90 09 08 00 34 90 01 01 8b 15 90 00 } //02 00 
		$a_01_2 = {ff 03 81 3b } //00 00 
	condition:
		any of ($a_*)
 
}