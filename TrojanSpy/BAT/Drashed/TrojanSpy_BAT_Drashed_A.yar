
rule TrojanSpy_BAT_Drashed_A{
	meta:
		description = "TrojanSpy:BAT/Drashed.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 01 00 "
		
	strings :
		$a_01_0 = {48 00 37 00 35 00 48 00 54 00 52 00 37 00 30 00 33 00 2d 00 } //01 00  H75HTR703-
		$a_01_1 = {5c 00 41 00 63 00 69 00 74 00 69 00 76 00 69 00 74 00 79 00 6c 00 6f 00 67 00 2e 00 78 00 6d 00 6c 00 } //01 00  \Acitivitylog.xml
		$a_01_2 = {50 00 69 00 6e 00 67 00 20 00 44 00 69 00 73 00 63 00 6f 00 6e 00 6e 00 65 00 63 00 74 00 2e 00 2e 00 2e 00 2e 00 2e 00 2e 00 } //01 00  Ping Disconnect......
		$a_01_3 = {2a 44 53 5f 4d 55 54 45 58 2d } //01 00  *DS_MUTEX-
		$a_01_4 = {12 84 fa 3f 82 a3 9f 9a 7d } //00 00 
		$a_00_5 = {a9 34 00 } //00 2f 
	condition:
		any of ($a_*)
 
}