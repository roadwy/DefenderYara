
rule Trojan_BAT_Norewor_A{
	meta:
		description = "Trojan:BAT/Norewor.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {6b 65 79 6c 6f 67 00 74 00 75 70 6c 6f 61 64 5f 73 65 72 76 65 72 00 6b 69 6c 6c 5f 6d 65 } //01 00  敫汹杯琀甀汰慯彤敳癲牥欀汩彬敭
		$a_01_1 = {2d 00 20 00 46 00 61 00 6b 00 65 00 20 00 69 00 6d 00 61 00 67 00 65 00 20 00 73 00 68 00 6f 00 77 00 6e 00 2e 00 2e 00 2e 00 } //01 00  - Fake image shown...
		$a_01_2 = {7c 00 57 00 44 00 4f 00 52 00 2b 00 4e 00 4f 00 52 00 52 00 45 00 } //00 00  |WDOR+NORRE
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}