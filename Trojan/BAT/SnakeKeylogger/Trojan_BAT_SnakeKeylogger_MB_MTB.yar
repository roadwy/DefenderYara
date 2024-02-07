
rule Trojan_BAT_SnakeKeylogger_MB_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 05 00 00 05 00 "
		
	strings :
		$a_01_0 = {57 15 a2 09 09 01 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 5e 00 00 00 0c 00 00 00 6c 00 00 00 57 00 00 00 53 } //02 00 
		$a_01_1 = {46 6f 72 74 75 64 65 53 65 63 6f 6e 64 2e 50 72 6f 70 65 72 74 69 65 73 } //02 00  FortudeSecond.Properties
		$a_01_2 = {4a 61 6d 62 6f } //02 00  Jambo
		$a_01_3 = {74 78 74 51 74 79 5f 4b 65 79 50 72 65 73 73 } //01 00  txtQty_KeyPress
		$a_01_4 = {54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b } //00 00  TransformFinalBlock
	condition:
		any of ($a_*)
 
}