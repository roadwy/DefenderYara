
rule Trojan_BAT_Netwire_ASQ_MTB{
	meta:
		description = "Trojan:BAT/Netwire.ASQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 07 00 00 0a 00 "
		
	strings :
		$a_03_0 = {07 11 04 20 00 38 01 00 5d 07 11 04 20 00 38 01 00 5d 91 08 11 04 1f 16 5d 6f 90 01 03 0a 61 28 90 01 03 0a 07 11 04 17 58 20 00 38 01 00 5d 91 28 90 01 03 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 90 01 03 0a 9c 00 11 04 15 58 13 04 11 04 16 fe 04 16 fe 01 13 05 11 05 2d a2 90 00 } //01 00 
		$a_81_1 = {49 44 65 66 65 72 72 65 64 } //01 00  IDeferred
		$a_81_2 = {5f 5a 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f 5f } //01 00  _Z_________________________________________
		$a_81_3 = {74 66 69 6e 61 6c } //01 00  tfinal
		$a_01_4 = {69 00 66 00 63 00 58 00 35 00 67 00 4c 00 45 00 54 00 } //01 00  ifcX5gLET
		$a_81_5 = {47 65 74 4d 65 74 68 6f 64 } //01 00  GetMethod
		$a_81_6 = {49 6e 76 6f 6b 65 } //00 00  Invoke
	condition:
		any of ($a_*)
 
}