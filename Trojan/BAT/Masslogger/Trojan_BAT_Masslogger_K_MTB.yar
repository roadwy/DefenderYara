
rule Trojan_BAT_Masslogger_K_MTB{
	meta:
		description = "Trojan:BAT/Masslogger.K!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 01 00 "
		
	strings :
		$a_80_0 = {42 6f 6d 62 4d 69 6e 65 } //BombMine  01 00 
		$a_80_1 = {4b 57 70 76 4f 2e 65 78 65 } //KWpvO.exe  01 00 
		$a_80_2 = {68 74 74 70 3a 2f 2f 74 65 6d 70 75 72 69 2e 6f 72 67 2f 44 61 74 61 53 65 74 31 2e 78 73 64 } //http://tempuri.org/DataSet1.xsd  01 00 
		$a_80_3 = {50 6f 6e 67 20 47 61 6d 65 20 62 79 20 50 61 75 6c 61 } //Pong Game by Paula  01 00 
		$a_80_4 = {71 75 61 72 61 6e 74 69 6e 65 65 34 } //quarantinee4  01 00 
		$a_80_5 = {6a 74 6e 4a 44 } //jtnJD  00 00 
	condition:
		any of ($a_*)
 
}