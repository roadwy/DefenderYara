
rule TrojanSpy_BAT_Flunuceo_B_bit{
	meta:
		description = "TrojanSpy:BAT/Flunuceo.B!bit,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 02 00 "
		
	strings :
		$a_01_0 = {59 6c 68 57 63 32 52 48 61 7a 30 3d 24 61 48 52 30 63 44 6f 76 4c 32 5a 79 5a 57 56 6e 5a 57 39 70 63 43 35 75 5a 58 51 76 61 6e 4e 76 62 69 38 3d } //01 00  YlhWc2RHaz0=$aHR0cDovL2ZyZWVnZW9pcC5uZXQvanNvbi8=
		$a_01_1 = {55 48 4a 76 59 32 56 7a 63 30 35 68 62 57 55 3d } //01 00  UHJvY2Vzc05hbWU=
		$a_01_2 = {55 32 68 70 5a 6e 52 4c 5a 58 6c 45 62 33 64 75 } //02 00  U2hpZnRLZXlEb3du
		$a_01_3 = {59 32 31 6b 4c 6d 56 34 5a 53 41 76 61 79 42 77 61 57 35 6e 49 44 41 67 4a 69 42 6b 5a 57 77 67 49 67 3d 3d } //00 00  Y21kLmV4ZSAvayBwaW5nIDAgJiBkZWwgIg==
	condition:
		any of ($a_*)
 
}