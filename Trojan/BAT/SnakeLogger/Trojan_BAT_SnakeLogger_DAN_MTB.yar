
rule Trojan_BAT_SnakeLogger_DAN_MTB{
	meta:
		description = "Trojan:BAT/SnakeLogger.DAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 03 00 "
		
	strings :
		$a_03_0 = {0d 16 13 09 2b 16 09 11 09 08 11 09 9a 1f 10 28 90 01 01 00 00 0a d2 9c 11 09 17 58 13 09 11 09 08 8e 69 fe 04 13 0a 11 0a 2d dd 90 00 } //02 00 
		$a_01_1 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 6c 69 63 61 74 69 6f 6e 31 2e 43 68 6f 69 63 65 50 72 6f 66 69 6c 65 2e 72 65 73 6f 75 72 63 65 73 } //00 00 
	condition:
		any of ($a_*)
 
}