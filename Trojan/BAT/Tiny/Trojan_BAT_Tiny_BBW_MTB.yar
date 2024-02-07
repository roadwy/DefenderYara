
rule Trojan_BAT_Tiny_BBW_MTB{
	meta:
		description = "Trojan:BAT/Tiny.BBW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 01 00 "
		
	strings :
		$a_02_0 = {73 29 00 00 0a 72 15 00 00 70 6f 2a 00 00 0a 80 08 00 00 04 7e 08 00 00 04 17 8d 90 01 01 00 00 01 25 16 1f 7c 9d 6f 2b 00 00 0a 16 9a 80 09 00 00 04 7e 08 00 00 04 17 8d 90 01 01 00 00 01 25 16 1f 7c 9d 6f 2b 00 00 0a 17 9a 80 0a 90 00 } //01 00 
		$a_00_1 = {00 00 04 28 04 00 00 06 6f 2c 00 00 0a 7e 09 00 00 04 1f 1a 28 2d 00 00 0a 72 59 00 00 70 28 2e 00 00 0a 6f 2f 00 00 0a 28 04 00 00 06 6f 2c 00 00 0a 7e 0a 00 00 04 1f 1a 28 2d 00 00 0a 72 67 00 00 70 28 2e 00 00 0a 6f 2f 00 00 0a } //01 00 
		$a_81_2 = {57 4f 52 4d } //00 00  WORM
	condition:
		any of ($a_*)
 
}