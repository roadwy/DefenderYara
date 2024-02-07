
rule Trojan_BAT_Styerlown_B{
	meta:
		description = "Trojan:BAT/Styerlown.B,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_01_0 = {6e 61 64 6f 50 72 6f 69 67 72 61 74 } //01 00  nadoProigrat
		$a_01_1 = {52 75 6e 53 6f 62 79 74 } //01 00  RunSobyt
		$a_01_2 = {55 00 73 00 6c 00 6f 00 76 00 73 00 42 00 65 00 7a 00 5a 00 61 00 70 00 79 00 61 00 74 00 6f 00 69 00 } //01 00  UslovsBezZapyatoi
		$a_01_3 = {74 00 61 00 73 00 6b 00 6d 00 6e 00 67 00 72 00 } //00 00  taskmngr
	condition:
		any of ($a_*)
 
}