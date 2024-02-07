
rule TrojanSpy_BAT_Cologger_A{
	meta:
		description = "TrojanSpy:BAT/Cologger.A,SIGNATURE_TYPE_PEHSTR,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {64 62 73 74 65 61 6c 65 72 } //01 00  dbstealer
		$a_01_1 = {73 74 65 61 6c 65 72 73 65 6e 64 } //01 00  stealersend
		$a_01_2 = {43 00 6f 00 6f 00 4c 00 6f 00 67 00 67 00 65 00 72 00 } //01 00  CooLogger
		$a_01_3 = {2a 00 6c 00 6f 00 67 00 6f 00 6e 00 6c 00 79 00 2a 00 } //00 00  *logonly*
	condition:
		any of ($a_*)
 
}