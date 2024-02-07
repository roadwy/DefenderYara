
rule TrojanSpy_BAT_Husabcar_A{
	meta:
		description = "TrojanSpy:BAT/Husabcar.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_01_0 = {79 00 6f 00 75 00 20 00 63 00 61 00 6e 00 20 00 66 00 69 00 6e 00 64 00 20 00 74 00 68 00 65 00 20 00 6f 00 77 00 6e 00 65 00 72 00 73 00 20 00 6f 00 66 00 20 00 75 00 6e 00 6b 00 6e 00 6f 00 77 00 6e 00 20 00 74 00 65 00 6c 00 65 00 70 00 68 00 6f 00 6e 00 65 00 20 00 6e 00 75 00 6d 00 62 00 65 00 72 00 73 00 20 00 65 00 61 00 73 00 69 00 6c 00 79 00 } //01 00  you can find the owners of unknown telephone numbers easily
		$a_01_1 = {55 00 59 00 47 00 55 00 4c 00 41 00 4d 00 41 00 4c 00 41 00 52 00 } //01 00  UYGULAMALAR
		$a_01_2 = {74 00 75 00 72 00 6b 00 74 00 75 00 63 00 63 00 61 00 72 00 2e 00 63 00 6f 00 6d 00 2f 00 73 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 2e 00 70 00 68 00 70 00 } //00 00  turktuccar.com/security.php
	condition:
		any of ($a_*)
 
}