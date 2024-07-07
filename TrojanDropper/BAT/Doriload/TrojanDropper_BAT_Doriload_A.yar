
rule TrojanDropper_BAT_Doriload_A{
	meta:
		description = "TrojanDropper:BAT/Doriload.A,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {6f 11 00 00 0a 26 09 6f 12 00 00 0a 72 1b 00 00 70 28 09 00 00 0a 72 25 00 00 70 28 0a 00 00 0a 28 13 00 00 0a de 03 26 de 00 2a 90 02 20 02 28 14 00 00 0a 2a 90 01 04 4d 5a 90 00 } //1
	condition:
		((#a_03_0  & 1)*1) >=1
 
}