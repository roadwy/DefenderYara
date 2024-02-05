
rule TrojanSpy_BAT_Evrial_A_bit{
	meta:
		description = "TrojanSpy:BAT/Evrial.A!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 01 00 "
		
	strings :
		$a_00_0 = {42 00 75 00 79 00 20 00 50 00 72 00 6f 00 6a 00 65 00 63 00 74 00 20 00 45 00 76 00 72 00 69 00 61 00 6c 00 } //01 00 
		$a_01_1 = {50 72 6f 6a 65 63 74 45 76 72 69 61 6c 2e 53 74 65 61 6c 65 72 } //01 00 
		$a_01_2 = {42 69 74 63 6f 69 6e 53 74 65 61 6c 65 72 } //01 00 
		$a_01_3 = {43 6c 69 70 62 6f 61 72 64 4d 6f 6e 69 74 6f 72 } //00 00 
	condition:
		any of ($a_*)
 
}