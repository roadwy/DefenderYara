
rule Trojan_BAT_XKeylogger_A_MTB{
	meta:
		description = "Trojan:BAT/XKeylogger.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {00 00 01 14 14 14 28 } //02 00 
		$a_01_1 = {00 00 01 13 4d 11 4d 16 14 a2 } //02 00 
		$a_01_2 = {11 4d 17 14 a2 } //02 00 
		$a_01_3 = {11 4d 14 14 14 28 } //00 00  䴑ᐔ⠔
	condition:
		any of ($a_*)
 
}