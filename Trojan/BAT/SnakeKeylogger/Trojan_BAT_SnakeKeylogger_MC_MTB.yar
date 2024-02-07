
rule Trojan_BAT_SnakeKeylogger_MC_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.MC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {09 69 8d 66 00 00 01 25 17 73 2c 00 00 0a 13 04 06 6f 90 01 03 0a 1f 0d 6a 59 13 05 07 06 11 04 11 05 09 90 00 } //05 00 
		$a_01_1 = {42 6f 75 6e 63 69 6e 67 42 61 6c 6c 73 2e 50 72 6f 70 65 72 74 69 65 73 } //05 00  BouncingBalls.Properties
		$a_01_2 = {57 ff a2 ff 09 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 7e 00 00 00 2b 00 00 00 cc 00 00 00 c7 } //00 00 
	condition:
		any of ($a_*)
 
}