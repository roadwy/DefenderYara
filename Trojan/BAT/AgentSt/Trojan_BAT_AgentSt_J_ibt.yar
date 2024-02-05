
rule Trojan_BAT_AgentSt_J_ibt{
	meta:
		description = "Trojan:BAT/AgentSt.J!ibt,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_03_0 = {1f 1a 28 10 00 00 0a 72 90 01 01 00 00 70 72 90 01 01 00 00 70 28 06 00 00 06 28 11 00 00 0a 13 07 90 00 } //01 00 
		$a_40_1 = {28 06 00 00 06 11 07 6f 12 00 00 0a 00 01 } //00 08 
		$a_11_2 = {28 14 00 00 0a 26 01 00 10 40 02 08 18 6f 16 00 00 0a 1f 10 28 17 00 00 0a 0d 01 00 1f 40 07 09 06 08 18 5b 06 6f 18 00 00 0a 5d 6f 19 00 00 0a 61 d1 8c 18 00 00 01 28 1a 00 00 0a 0b 00 00 5d } //04 00 
	condition:
		any of ($a_*)
 
}