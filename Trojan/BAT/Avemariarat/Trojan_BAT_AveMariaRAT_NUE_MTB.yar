
rule Trojan_BAT_AveMariaRAT_NUE_MTB{
	meta:
		description = "Trojan:BAT/AveMariaRAT.NUE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 01 00 "
		
	strings :
		$a_03_0 = {03 02 20 00 22 00 00 04 28 90 01 03 06 03 04 17 58 20 00 22 00 00 5d 91 28 90 00 } //01 00 
		$a_01_1 = {56 6f 72 6f 6e 69 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 } //01 00  Voroni.Properties.Resources.r
		$a_81_2 = {33 38 46 34 57 50 39 45 34 48 48 38 35 38 46 41 53 43 4a 53 42 35 } //01 00  38F4WP9E4HH858FASCJSB5
		$a_81_3 = {52 6f 73 74 69 73 61 } //01 00  Rostisa
		$a_81_4 = {47 65 74 4d 65 74 68 6f 64 73 } //01 00  GetMethods
		$a_81_5 = {74 6f 64 6f 2e 74 78 74 } //00 00  todo.txt
	condition:
		any of ($a_*)
 
}