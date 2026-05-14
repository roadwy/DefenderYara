
rule Trojan_BAT_SlowGambler_A_dha{
	meta:
		description = "Trojan:BAT/SlowGambler.A!dha,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 04 17 58 13 04 11 04 17 59 13 04 11 04 17 58 13 04 11 04 17 58 13 04 11 04 20 80 96 98 00 31 df } //1
	condition:
		((#a_01_0  & 1)*1) >=1
 
}