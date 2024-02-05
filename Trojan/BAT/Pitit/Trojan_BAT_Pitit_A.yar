
rule Trojan_BAT_Pitit_A{
	meta:
		description = "Trojan:BAT/Pitit.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 01 00 "
		
	strings :
		$a_03_0 = {1d 28 1d 00 00 0a 72 90 01 01 00 00 70 72 90 01 01 00 00 70 28 1e 00 00 0a 28 1f 00 00 0a 0a 28 04 00 00 06 6f 20 00 00 0a 02 7b 06 00 00 04 06 6f 21 00 00 0a de 90 00 } //00 00 
	condition:
		any of ($a_*)
 
}