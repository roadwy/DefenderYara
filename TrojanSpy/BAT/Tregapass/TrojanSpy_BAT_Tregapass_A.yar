
rule TrojanSpy_BAT_Tregapass_A{
	meta:
		description = "TrojanSpy:BAT/Tregapass.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_80_0 = {68 65 6e 72 69 71 75 65 2e 77 68 65 65 6c 73 40 79 61 68 6f 6f 2e 63 6f 6d } //henrique.wheels@yahoo.com  01 00 
		$a_80_1 = {6c 6f 67 69 6e 70 61 73 73 77 6f 72 64 } //loginpassword  01 00 
		$a_80_2 = {50 68 6c 6d 32 30 31 30 } //Phlm2010  00 00 
		$a_00_3 = {5d 04 } //00 00  ѝ
	condition:
		any of ($a_*)
 
}