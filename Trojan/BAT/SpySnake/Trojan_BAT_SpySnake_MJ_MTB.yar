
rule Trojan_BAT_SpySnake_MJ_MTB{
	meta:
		description = "Trojan:BAT/SpySnake.MJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 05 00 "
		
	strings :
		$a_01_0 = {5d 94 13 07 09 11 05 08 11 05 91 11 07 61 d2 9c 11 05 17 58 13 05 11 05 08 8e 69 32 95 } //00 00 
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_SpySnake_MJ_MTB_2{
	meta:
		description = "Trojan:BAT/SpySnake.MJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 0a 00 "
		
	strings :
		$a_03_0 = {0a 00 06 72 c8 03 00 70 7d 27 00 00 04 28 90 01 03 06 06 fe 06 30 00 00 06 73 1b 00 00 0a 28 90 01 03 2b 28 90 01 03 2b 0b 07 28 90 01 03 06 6f 90 01 03 0a 0c 12 02 28 90 01 03 0a 00 2a 90 00 } //01 00 
		$a_01_1 = {24 00 50 00 41 00 53 00 53 00 57 00 4f 00 52 00 44 00 24 00 } //01 00  $PASSWORD$
		$a_01_2 = {47 65 74 4c 6f 67 67 65 72 } //01 00  GetLogger
		$a_01_3 = {53 63 33 65 65 6e } //01 00  Sc3een
		$a_01_4 = {54 68 72 65 61 64 53 74 61 72 74 } //00 00  ThreadStart
	condition:
		any of ($a_*)
 
}
rule Trojan_BAT_SpySnake_MJ_MTB_3{
	meta:
		description = "Trojan:BAT/SpySnake.MJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 01 00 "
		
	strings :
		$a_03_0 = {01 25 16 d0 90 01 01 00 00 01 28 90 01 03 0a 90 0a 35 00 d0 12 00 00 01 28 90 01 03 0a 72 90 01 01 00 00 70 72 90 01 01 00 00 70 72 90 01 01 00 00 70 28 90 01 04 17 8d 90 02 12 a2 28 90 01 03 0a 73 90 01 01 00 00 0a 17 8d 90 01 01 00 00 01 25 16 72 90 01 01 00 00 70 a2 6f 90 01 03 0a 74 90 01 01 00 00 1b 90 00 } //01 00 
		$a_01_1 = {52 65 70 6c 61 63 65 } //01 00  Replace
		$a_01_2 = {49 6e 76 6f 6b 65 } //01 00  Invoke
		$a_01_3 = {52 65 76 65 72 73 65 } //00 00  Reverse
	condition:
		any of ($a_*)
 
}