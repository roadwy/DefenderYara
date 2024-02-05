
rule Trojan_BAT_Androm_J_ibt{
	meta:
		description = "Trojan:BAT/Androm.J!ibt,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_42_0 = {07 06 07 91 1f 90 01 01 61 d2 9c 90 00 01 } //00 10 
		$a_28_1 = {00 00 0a 7e 01 00 00 04 6f 10 00 00 0a 0a 01 00 18 40 02 74 16 00 00 01 6f 19 00 00 0a 14 16 8d 01 00 00 01 6f 1a 00 00 0a 26 00 00 5d 04 00 00 a7 eb 03 80 5c 25 00 00 a8 eb 03 80 00 00 01 00 } //08 00 
	condition:
		any of ($a_*)
 
}