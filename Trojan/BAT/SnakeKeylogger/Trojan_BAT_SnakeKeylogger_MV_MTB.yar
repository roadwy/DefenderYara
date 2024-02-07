
rule Trojan_BAT_SnakeKeylogger_MV_MTB{
	meta:
		description = "Trojan:BAT/SnakeKeylogger.MV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 03 00 00 05 00 "
		
	strings :
		$a_03_0 = {07 06 08 8f 6f 00 00 01 28 90 01 03 0a 28 90 01 03 0a 0b 00 08 17 59 0c 08 15 fe 02 0d 09 2d df 07 13 04 2b 00 11 04 2a 90 00 } //02 00 
		$a_01_1 = {30 35 64 35 39 34 63 35 2d 32 66 61 64 2d 34 66 37 61 2d 38 34 65 31 2d 61 30 61 63 66 64 37 36 37 66 30 36 } //02 00  05d594c5-2fad-4f7a-84e1-a0acfd767f06
		$a_01_2 = {43 6f 6e 77 61 79 5f 73 5f 47 61 6d 65 2e 50 72 6f 70 65 72 74 69 65 73 } //00 00  Conway_s_Game.Properties
	condition:
		any of ($a_*)
 
}