
rule Trojan_BAT_SnakeKeylogger_MR_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.MR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 05 00 "
		
	strings :
		$a_03_0 = {08 11 06 07 11 06 9a 1f 10 28 90 01 03 0a d2 9c 11 06 17 58 13 06 11 06 07 8e 69 fe 04 13 07 11 07 2d dd 90 00 } //01 00 
		$a_01_1 = {32 64 64 30 36 37 32 39 2d 34 36 38 34 2d 34 34 31 65 2d 61 37 30 30 2d 39 63 62 62 63 66 66 66 37 65 64 39 } //01 00  2dd06729-4684-441e-a700-9cbbcfff7ed9
		$a_01_2 = {52 75 6e 5f 43 6c 69 63 6b } //01 00  Run_Click
		$a_01_3 = {54 72 79 61 41 67 61 69 6e 2e 50 72 6f 70 65 72 74 69 65 73 } //00 00  TryaAgain.Properties
	condition:
		any of ($a_*)
 
}